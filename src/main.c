#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/poll.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <sys/resource.h>

#include <sys/ioctl.h>

#include "xdp_loader.h"
#include "xdp_util.h"
#include "yara_scan.h"

// NIC 개수
#define MAX_IF       2
// YARA Rule (compiled)
#define FILE_YARA_RULE   "/etc/yara/rules/compiled_rules.yarc"

// Blocklist 메크로
#define BLOCK_DURATION_SEC 60  // 60초 후 자동 해제
#define MAX_BLOCKLIST 16384    // Blocklist 개수

// 종료 플래그
static int g_exit = 1;

// 포워딩 구조체
struct fwd_args 
{ 
	struct xsk_socket_info *src; 
	struct xsk_socket_info *dst; 
};

// ---------- Blocklist---------------
// Blocklist 구조체
typedef struct _block_entry 
{
	__u64 flow_id;     // flow id
	time_t expire_ts;  // 해제 시간
	uint32_t ifindex;  // 해당 NIC의 ifindex
} SPMD_ENTRY;


static SPMD_ENTRY blocklist_array[MAX_BLOCKLIST]; // Blocklist 배열
static pthread_mutex_t blocklist_mutex = PTHREAD_MUTEX_INITIALIZER;  // Blocklist 뮤텍스

// Flow id 생성 함수
static __always_inline __u64 make_flow_id(__u32 sip, __u32 dip,
		__u16 dport,
		__u8 proto) 
{
	__u64 v = sip;
	v = (v << 32) ^ dip;
	v ^= ((__u64)dport << 16) ^ proto;
	v ^= (v >> 33);
	v *= 0xff51afd7ed558ccdULL;
	v ^= (v >> 33);

	return v;
}
// ---------- Blocklist---------------


// mlock(), shmctl() 메모리 크기 확보
static int pmd_raise_rlimit(void) 
{
	//RLIMIT_MEMLOCK : CPY_SYS_IPC 설정없이 
	//mlock(), shmctl()등으로 가질수 있는 메모리 크기
	struct rlimit r = { 
		RLIM_INFINITY, 
		RLIM_INFINITY 
	};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) 
	{
		perror("setrlimit");
		return -1;
	}

	return 0;
}

// NIC의 MAC 주소 가져오는 함수
static int pmd_get_if_hwaddr(const char *ifname, unsigned char *mac) 
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
	{
		perror("Failed to create socket");
		return 1;
	}

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	// MAC 주소 가져오기
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if ( ret < 0 ) 
	{
		perror("Failed to get MAC address");
		return 1;
	}

	// MAC 주소 출력
	mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
	//printf("My MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	//		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	close(sockfd);

	return 0;
}

// IP의 MAC 주소를 가져오는 함수
int pmd_get_mac_address(const char *ip_addr, uint8_t mac[6]) 
{
	char line[256];
	char ip[32], hw_type[8], flags[8], mac_str[32], mask[32], device[32];
	FILE *fp = NULL;

	fp = fopen("/proc/net/arp", "r");

	if ( !fp ) 
	{
		perror("fopen(/proc/net/arp)");
		return 0;
	}

	fgets( line, sizeof(line), fp ); // skip header

	while ( fgets(line, sizeof(line), fp) ) 
	{
		if ( sscanf(line, "%31s %7s %7s %31s %31s %31s",
					ip, hw_type, flags, mac_str, mask, device) != 6 )
			continue;

		if ( strcmp(ip, ip_addr) == 0 ) 
		{
			if ( sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
						&mac[0], &mac[1], &mac[2],
						&mac[3], &mac[4], &mac[5]) == 6 ) 
			{
				fclose(fp);

				return 1;
			}
		}
	}

	fclose(fp);

	return 0;
}

// SRC/DST MAC 주소 변경함수
static inline void pmd_change_mac_l2(unsigned char *frame,
		const unsigned char dst[ETH_ALEN],
		const unsigned char src[ETH_ALEN])
{
	struct ethhdr *eth = (struct ethhdr *)frame;

	memcpy(eth->h_dest, dst, ETH_ALEN);
	memcpy(eth->h_source, src, ETH_ALEN);
}

// RX/TX 소켓에 연결된 Fill/Comp Ring 프래임 관리
static inline void pmd_reuse_ring(struct xsk_socket_info *rxp, struct xsk_socket_info *txp)
{
	// Ring 고갈 방지: 틈틈이 드레인/보충
	
	// RX/TX 소켓에 연결된 Comp Ring 프래임 재회수
	xsk_recycle_tx_completions(&rxp->umem);
	xsk_recycle_tx_completions(&txp->umem);

	// RX/TX 소켓에 연결된 Fill Ring 프래임 재할당 
	xsk_topup_fill_ring(&rxp->umem);
	xsk_topup_fill_ring(&txp->umem);
}


// 악성코드 분석 비동기 완료 콜백
static void pmd_yara_on_scanned(int match, void *user) 
{
	int ret = 0, i = 0;

	YARA_JOB_CTX *ctx = (YARA_JOB_CTX *)user;
	struct xsk_socket_info *sock = (struct xsk_socket_info *)ctx->rxp;

	if (!ctx || !ctx->rxp) 
		return;

	if (ctx->rx_addr == 0) 
		return; // 이미 재활용된 프래임 주소

	if ( !g_exit ) 
		return;

	if (match) 
	{
		// blocklist_map에 차단 대상 등록
		ret = bpf_map_update_elem(ctx->blocklist_fd, &ctx->flow_id, &ctx->bl_val, BPF_ANY);

		printf("DROP 2 Packet:%s\n", ctx->buffer );
		if ( ret < 0 ) 
		{
			perror("bpf_map_update_elem(blocklist)");
		}

		// 유저 공간 blocklist 기록
		pthread_mutex_lock(&blocklist_mutex);
		for ( i = 0; i < MAX_BLOCKLIST; i++ ) 
		{
			// 같은 flow id가 있으면 차단 유지 시간 갱신
			if ( blocklist_array[i].flow_id == ctx->flow_id )
			{
				blocklist_array[i].expire_ts = time(NULL) + BLOCK_DURATION_SEC;
				break;
			}
			// 신규 등록
			else if ( blocklist_array[i].flow_id == 0 || blocklist_array[i].expire_ts < time(NULL)) 
			{
				blocklist_array[i].flow_id = ctx->flow_id;
				blocklist_array[i].expire_ts = ctx->expire_ts;
				blocklist_array[i].ifindex = ctx->ifindex;  // 등록한 NIC ifindex 저장
				break;
			}
		}
		pthread_mutex_unlock(&blocklist_mutex);

	}

	xsk_recycle_fill_ring(sock, ctx->rx_addr, ctx->consumed_rx);

	xsk_recycle_tx_completions(&sock->umem);
	xsk_topup_fill_ring(&sock->umem);

	free(ctx);
}

// 단방향 포워딩: rxp -> txp
// enp0s3 -> enp0s8 또는 enp0s8 -> enp0s3
static void pmd_forward_once(struct xsk_socket_info *rxp, struct xsk_socket_info *txp)
{
	__u32 idx_tx = 0;
	__u32 idx_rx = 0;

	__u64 tx_addr = 0;
	__u64 rx_addr = 0;
	__u32 rx_len  = 0;

	__u16 sport = 0;
	__u16 dport = 0;

	__u64 flow_id; // blocklist_map에서 사용할 key
	__u8 val = 1;

	uint64_t data_addr = 0;

	unsigned int i = 0;
	unsigned int rcvd = 0;

	struct xdp_desc *txd = NULL;
	const struct xdp_desc *rxd = NULL;
	void *rx_data = NULL;
	void *tx_data = NULL;

	uint8_t dst_mac[6];

	char buffer[MAX_BUFF];
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct icmphdr *icmph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	// 악성코드 검사
	int sret = 0;

	// 처리한 RX 수(정확 릴리즈용)
	unsigned int consumed_rx = 0;

	// 처리할 TX 수(정확 릴리즈용)
	unsigned int consumed_tx = 0;

	uint32_t ihl = 0;

	if ( !g_exit ) 
		return;

	rcvd = xsk_ring_cons__peek(&rxp->rx, BATCH, &idx_rx);
	if ( !rcvd ) 
		return;

	// 링이 마르지 않도록 선제적으로 드레인/보충
	pmd_reuse_ring(rxp, txp);

	for ( i = 0; i < rcvd; i++ ) 
	{
		rxd = xsk_ring_cons__rx_desc(&rxp->rx, idx_rx + i);
		rx_addr = rxd->addr;
		rx_len  = rxd->len;

		if ( !g_exit ) 
			break;

		if (rx_len < ETH_HLEN) 
		{
			// Fill Ring 프래임 재할당
			xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );
			continue;
		}

		// RX 데이터 포인터 (rxp UMEM 기준)
		data_addr = xsk_umem__add_offset_to_addr(rx_addr);
		rx_data   = xsk_umem__get_data(rxp->umem.buffer, data_addr);

		// Fill Ring 프래임 재할당 후 다음 패킷 처리
		if (!rx_data) 
		{ 
			xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );
			continue;
		}

		// Ethernet 해더 
		eth = (struct ethhdr *)rx_data;
		if ( ntohs(eth->h_proto) == ETH_P_IP ) 
		{
			// IP 해더
			iph = (struct iphdr *)(rx_data + sizeof(struct ethhdr));
			ihl = (iph->ihl & 0x0F) * 4;
			inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));

			memset( buffer, 0x00, sizeof(buffer) );

			switch ( iph->protocol) 
			{ 
				case IPPROTO_ICMP: 
					icmph = (struct icmphdr *)((uint8_t*)iph + ihl);
					snprintf(buffer, sizeof(buffer), 
							"PROTO:[%s] SRC:(%02x:%02x:%02x:%02x:%02x:%02x) [%s] "
							"--> DST:(%02x:%02x:%02x:%02x:%02x:%02x) [%s]",
							"ICMP", eth->h_source[0], eth->h_source[1], eth->h_source[2],
							eth->h_source[3], eth->h_source[4], eth->h_source[5], src_ip,
							eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
							eth->h_dest[3], eth->h_dest[4], eth->h_dest[5], dst_ip );
					break;
				case IPPROTO_TCP: 
					tcph = (struct tcphdr*)((uint8_t*)iph + ihl);
					snprintf(buffer, sizeof(buffer), 
							"PROTO:[%s] SRC:(%02x:%02x:%02x:%02x:%02x:%02x) [%s:%d] "
							"--> DST:(%02x:%02x:%02x:%02x:%02x:%02x) [%s:%d]",
							"TCP", eth->h_source[0], eth->h_source[1], eth->h_source[2],
							eth->h_source[3], eth->h_source[4], eth->h_source[5], src_ip, ntohs(tcph->source),
							eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
							eth->h_dest[3], eth->h_dest[4], eth->h_dest[5], dst_ip, ntohs(tcph->dest)  );
					sport = ntohs(tcph->source);
					dport = ntohs(tcph->dest);
					break;
				case IPPROTO_UDP: 
					udph = (struct udphdr*)((uint8_t*)iph + ihl);
					snprintf(buffer, sizeof(buffer), 
							"PROTO:[%s] SRC:(%02x:%02x:%02x:%02x:%02x:%02x)[%s:%d] "
							"--> DST:(%02x:%02x:%02x:%02x:%02x:%02x)[%s:%d]",
							"UDP", eth->h_source[0], eth->h_source[1], eth->h_source[2],
							eth->h_source[3], eth->h_source[4], eth->h_source[5], src_ip, ntohs(udph->source),
							eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
							eth->h_dest[3], eth->h_dest[4], eth->h_dest[5], src_ip, ntohs(udph->dest)  );
					sport = ntohs(udph->source);
					dport = ntohs(udph->dest);
					break;
			}

		}

		// IP 프로토콜, 정상 IP 헤뎌, TCP/UDP 인 경우 악성코드 탐지 실랭
		if ( ( ntohs(eth->h_proto) == ETH_P_IP && rx_len >= (ETH_HLEN + sizeof(struct iphdr)) ) &&  
				( iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP ) )
		{

			// blocklist_map에 등록할 key(flow_id), val 값 설정
			val = 1;
			flow_id = make_flow_id( iph->saddr, iph->daddr, dport, iph->protocol);

			// blocklist_map에 Drop 정보 있는지 확인
			__u8 blk = bpf_map_lookup_elem( rxp->blocklist_fd, &flow_id, &val);

			// blocklist_map에 Drop 정보가 있으면 차단 유지 시간 갱신
			if ( blk == 0 )
			{
				printf("DROP 1 Packet:%s\n", buffer );

				// 유저 공간 blocklist 기록
				pthread_mutex_lock(&blocklist_mutex);
				for ( i = 0; i < MAX_BLOCKLIST; i++ ) 
				{
					blocklist_array[i].flow_id = flow_id;
					blocklist_array[i].expire_ts = time(NULL) + BLOCK_DURATION_SEC;
					blocklist_array[i].ifindex = rxp->ifindex;  // 등록한 NIC ifindex 저장
				}
				pthread_mutex_unlock(&blocklist_mutex);

				xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );

				// 링 고갈 방지: 틈틈이 드레인/보충
				xsk_recycle_tx_completions(&txp->umem);

				// RX 소켓에 연결된 Fill Ring 재할당
				// 프래임 버퍼 재할당
				xsk_topup_fill_ring(&rxp->umem);

				continue;
			}

			//
			// blocklist_map에 drop 정보 없으면 악성코드 검사
			// 

			// 워커 풀로 검사에 맡기기 위한 메모리 할당
			//    주의: rx_data 포인터는 콜백(pmd_yara_on_scanned) 완료까지 유효 필수
			YARA_JOB_CTX *ctx = (YARA_JOB_CTX *)calloc(1, sizeof(*ctx));

			if ( !ctx ) 
			{
				// RX Ring 프래임 재할당 설정
				xsk_recycle_fill_ring(rxp, rx_addr, &consumed_rx);

				// TX 소켓에 연결된 Comp Ring 프래임 재회수
				// Ring 고갈 방지: 틈틈이 드레인/보충
				xsk_recycle_tx_completions(&txp->umem);

				xsk_topup_fill_ring(&rxp->umem);

				continue;
			}

			// 비동기 악성코드 분석 관련 데이터 설정
			ctx->rxp          = rxp;          // RX 소켓 정보
			ctx->rx_addr      = rx_addr;      // RX Ring 주소
			ctx->buffer       = buffer;       // 로깅버퍼
			ctx->rx_data      = rx_data;      // RX Data
			ctx->rx_len       = rx_len;       // RX Data 길이
			ctx->blocklist_fd = rxp->blocklist_fd; // blocklist_map에 연결한 소켓 fd
			ctx->flow_id      = flow_id;      // blocklist_map의 key 값을 쓸 flow_id
			ctx->bl_val       = 1;            // blocklist_map의 val 값

			ctx->expire_ts    = time(NULL) + BLOCK_DURATION_SEC; // 차단 해제 시간
			ctx->ifindex      = rxp->ifindex; // NIC index
			ctx->consumed_rx  = &consumed_rx; // 처리한 RX 수

			// 워커 폴에 제출
			sret = yara_submit(ctx->rx_data, ctx->rx_len, pmd_yara_on_scanned, ctx);

			if ( sret != 0 ) 
			{
				xsk_recycle_fill_ring(rxp, rx_addr, &consumed_rx);

				// TX 소켓에 연결된 Comp Ring 프래임 재회수
				// Ring 고갈 방지: 틈틈이 드레인/보충
				xsk_recycle_tx_completions(&txp->umem);

				xsk_topup_fill_ring(&rxp->umem);

				free(ctx);

				continue;
			}

			// 목적지 IP의 MAC 주소 가져오기
			if ( pmd_get_mac_address(dst_ip, dst_mac) ) 
			{
				pmd_change_mac_l2(rx_data, dst_mac, txp->if_mac);
				printf("FORWARD Packet:%s\n", buffer );
				printf("[MAC] IP:%s 의 MAC을 갱신했습니다. MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
						dst_ip,
						dst_mac[0], dst_mac[1], dst_mac[2],
						dst_mac[3], dst_mac[4], dst_mac[5]);
			} else {
				fprintf(stderr, "[MAC] %s 의 MAC을 찾을 수 없습니다.\n", dst_ip);

				xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );

				// TX 소켓에 연결된 Comp Ring 재회수
				// Ring 고갈 방지: 틈틈이 드레인/보충
				xsk_recycle_tx_completions(&txp->umem);

				xsk_topup_fill_ring(&rxp->umem);

				continue;
			}
		}

		// TX용 프레임 1개 할당(부족 시 한 번 정리 후 재시도)
		tx_addr = xsk_frame_alloc(&txp->umem);
		if (tx_addr == (__u64)-1) 
		{
			// 완료 드레인 후 재시도
			xsk_recycle_tx_completions(&txp->umem);
			tx_addr = xsk_frame_alloc(&txp->umem);

			if (tx_addr == (__u64)-1) 
			{
				// 여전히 부족하면 이번 프레임만 재충전하고 종료(헤드-오브-라인 방지)
				xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );
				break;
			}
		}

		// TX desc 1개 예약(부족 시 한 번 정리 후 재시도)
		idx_tx = 0;
		if (!xsk_ring_prod__reserve(&txp->tx, 1, &idx_tx)) 
		{
			xsk_recycle_tx_completions(&txp->umem);

			if (!xsk_ring_prod__reserve(&txp->tx, 1, &idx_tx)) 
			{
				// 실패 시 TX 프레임 반환하고 이번 프레임만 재충전
				xsk_frame_free(&txp->umem, tx_addr);

				xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );
				break;
			}
		}

		// TX 데이터 포인터
		tx_data = xsk_umem__get_data(txp->umem.buffer, tx_addr);

		// RX 프레임의의 패킷 데이터를 TX 프레임에 복사(UMEM 분리 환경)
		memcpy((uint8_t*)tx_data, (uint8_t*)rx_data, rx_len);

		// TX desc 내용 설정 후 전송 제출
		txd = xsk_ring_prod__tx_desc(&txp->tx, idx_tx);
		txd->addr = tx_addr;
		txd->len  = rx_len;
		
		// 처리할 TX 수 증가
		consumed_tx++;

		// RX Ring 프레임은 즉시 재할당
		xsk_recycle_fill_ring( rxp, rx_addr, &consumed_rx );


	}

	// 테이터 전송
	xsk_ring_prod__submit(&txp->tx, consumed_tx);

	// TX NIC 깨우기
	xsk_kick_tx_if_needed(txp);

	// RX 릴리즈(실제 소비한 만큼)
	if (consumed_rx)
		xsk_ring_cons__release(&rxp->rx, consumed_rx);
	else
		xsk_ring_cons__release(&rxp->rx, rcvd);

	pmd_reuse_ring(rxp, txp);
}

// RX/TX 소켓에 연결된 Fill/Comp Ring 프래임 관리 쓰레드
static void *pmd_recycler_thread(void *arg) 
{

	struct fwd_args *fa = (struct fwd_args *)arg;
	struct xsk_socket_info *rxp = fa->src;
	struct xsk_socket_info *txp = fa->dst;

	while (g_exit)
	{
		pmd_reuse_ring(rxp, txp);
		usleep(3);
	}

	return NULL;

}

// blocklist 해제 함수
static void *pmd_blocklist_cleanup_thread(void *arg) 
{

	int fd = 0;
	int i = 0, j = 0;
	time_t now = 0;
	struct fwd_args *fa = (struct fwd_args *)arg;
	struct xsk_socket_info *socks[MAX_IF] = { fa->src, fa->dst };

	uint32_t ifidx = 0;
	__u64 fid = 0;

	while (g_exit) 
	{
		now = time(NULL);
		pthread_mutex_lock(&blocklist_mutex);

		for ( i = 0; i < MAX_BLOCKLIST; i++) 
		{
			if ( blocklist_array[i].flow_id != 0 && blocklist_array[i].expire_ts <= now ) 
			{
				fid = blocklist_array[i].flow_id;
				ifidx = blocklist_array[i].ifindex;
				fd = -1;

				// sockets 배열에서 ifindex와 일치하는 소켓 찾기
				for ( j = 0 ; j < MAX_IF ; j++ ) 
				{
					if ( socks[j]->ifindex == ifidx) {
						fd = socks[j]->blocklist_fd;
						break;
					}
				}

				if (fd >= 0) 
					bpf_map_delete_elem(fd, &fid);  // 커널 map에서 삭제

				blocklist_array[i].flow_id = 0;
				blocklist_array[i].expire_ts = 0;
				blocklist_array[i].ifindex = 0;
			}
		}
		pthread_mutex_unlock(&blocklist_mutex);
		usleep(500*1000); // 0.5초
	}
	return NULL;

}

// 포워드 및 악성코드 검사 쓰레드
static void *pmd_forward_thread(void *arg) 
{

	int ret = 0;
	int timeout_ms = 5;

	struct fwd_args *fa = (struct fwd_args *)arg;
	struct xsk_socket_info *rxp = fa->src;
	struct xsk_socket_info *txp = fa->dst;

	struct pollfd fds[2] = {
		{ .fd = rxp->xsk_fd, .events = POLLIN | POLLERR | POLLHUP },
		{ .fd = txp->xsk_fd, .events = POLLIN | POLLERR | POLLHUP },
	};

	while (g_exit) 
	{
		// 하우스키핑만
		pmd_reuse_ring(rxp, txp);
		if (xsk_ring_prod__needs_wakeup(&rxp->tx)) 
			xsk_kick_tx_if_needed(rxp);

		if (xsk_ring_prod__needs_wakeup(&txp->tx)) 
			xsk_kick_tx_if_needed(txp);

		ret = poll(fds, 2, timeout_ms);

		if ( ret < 0 ) 
		{ 
			if (errno == EINTR) 
				continue; 

			perror("poll"); 
			break; 
		}

		if ( ret == 0 ) 
			continue;

		if (fds[0].revents & (POLLERR|POLLHUP)) 
			break;

		if (fds[1].revents & (POLLERR|POLLHUP)) 
			break;

		pmd_reuse_ring(rxp, txp);

		if (fds[0].revents & POLLIN) 
			pmd_forward_once(rxp, txp);

		if (fds[1].revents & POLLIN) 
			pmd_forward_once(txp, rxp);

	}

	return NULL;  

}

// 자원 정리 함수
static void pmd_cleanup(struct xsk_socket_info *psock) 
{
	int i = 0;
	__u32 k = 0;

	yara_workers_stop();
	yara_finalize();

	for ( i = 0 ; i < MAX_IF ; i++ )
	{
		k = psock[i].queue_id;
		bpf_map_delete_elem(psock[i].xsks_map_fd, &k);
		xdp_unload_program(&psock[i]); 
		xsk_socket_cleanup(&psock[i]); 
	}
}

// 신호 핸들러 함수
static void pmd_sig_handler(int signo) 
{
	(void)signo;

	g_exit = 0;
}

// 메인 함수
int main( int argc, char **argv )
{

	int i = 0;
	int ret = 0;
	//const char *ifname[MAX_IF] = { "enp0s3", "enp0s8" };
	uint32_t queue_id = 0;

	const char *xdp_obj = "xdp_prog_kern.o"; /* 사용자가 준비한 XDP 오브젝트 */
	const char *xdp_sec = "xdp";             /* 섹션 이름 */
	const char *xdp_map = "xsks_map";        /* map 이름 */
	struct xsk_socket_info socks[MAX_IF];

	pthread_t th_forward[MAX_IF], th_block[MAX_IF], th_rc;
	struct fwd_args forward[MAX_IF];

	signal(SIGINT, pmd_sig_handler);
	signal(SIGTERM, pmd_sig_handler);

	// NIC 확인
	if ( argc != 3 )
	{
		fprintf(stderr, "Usage: %s <NIC 1> <NIC 2>\n", basename(argv[0]) );
		return 1;
	}

	// Yara Rlue 초기화
	ret = yara_init(FILE_YARA_RULE);
	if ( ret != 0 )
		return 1;

	if (yara_workers_start(4) != 0) 
	{
		fprintf(stderr, "YARA 워커 시작 실패\n");
		return -1;
	}

	if (pmd_raise_rlimit() ) return 1;

	fprintf(stderr, "<================> Start XDP SPMD <================>\n");
	fprintf(stderr, "Bridge up: %s <-> %s (queue %u, SKB/COPY)\n",
	        argv[1], argv[2], queue_id);

	for ( i = 0 ; i < MAX_IF ; i++ )
	{
		// 각 NIC 이름 가져오기
		strncpy( socks[i].ifname, argv[i + 1], IFNAMSIZ - 1);
		socks[i].queue_id = queue_id;

		// 각 NIC MAC 주소 가져오기
		if ( pmd_get_if_hwaddr(socks[i].ifname, socks[i].if_mac) ) 
		{
			fprintf(stderr, "pmd_get_if_hwaddr(%s) failed\n", socks[i].ifname);
			return 1;
		}

		// NIC 별로 UMEM 생성
		if ( xsk_configure_umem(&socks[i].umem) ) 
			return 1;

		// XSK 소켓 생성 (각각 자기 UMEM 사용)
		if ( xsk_configure_socket(&socks[i]) ) 
			return 1;

		// 각 NIC에 별도 XDP 프로그램 인스턴스 attac + xsks_map 등록 
		if ( xdp_load_program(&socks[i], xdp_obj, xdp_sec, xdp_map) ) 
			return 1;

		// 스레드 기동
		forward[i].src = &socks[i];
		forward[i].dst = &socks[1 - i];

		if ( pthread_create(&th_forward[i], NULL, pmd_forward_thread, &forward[i]) != 0) 
		{
			perror("pthread_create a2b"); 
			return 1;
		}

		if ( pthread_create(&th_block[i], NULL, pmd_blocklist_cleanup_thread, &forward[i]) != 0 ) 
		{
			perror("pthread_create cleanup thread");
			return 1;
		}

	}

	if ( pthread_create(&th_rc,  NULL, pmd_recycler_thread, &forward[0]) != 0) 
		perror("pthread_create recycler"); 

	for ( i = 0 ; i < MAX_IF ; i++ )
	{
		pthread_join(th_forward[i], NULL);
		pthread_join(th_block[i], NULL);

	}
	pthread_join(th_rc,  NULL);

	pmd_cleanup( socks );

	return 0;

}
