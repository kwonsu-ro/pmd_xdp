// af_xdp_util.c - AF_XDP 유틸리티 함수 구현
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/mman.h>

#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "xdp_util.h"

// 프래임 값 할당
__u64 xsk_umem_frame_addr(uint32_t idx) 
{
	return (__u64)idx * FRAME_SIZE;
}


// 전송 프레임을 UMEM에서 하나 해제하는 함수
void xsk_frame_free(struct xsk_umem_info *pumem, __u64 addr) 
{
	if ( pumem->head < pumem->frame_cnt )
		pumem->frame_addrs[pumem->head++] = addr;
}

// 전송 프레임을 UMEM에서 하나 할당하는 함수
__u64 xsk_frame_alloc(struct xsk_umem_info *pumem) 
{
	if (pumem->head == 0) 
		return (__u64)-1;

	return pumem->frame_addrs[--pumem->head];
}

// 전송 프레임 초기화 함수
int xsk_frame_pool_init(struct xsk_umem_info *pumem)
{
	pumem->frame_addrs = calloc(NUM_FRAMES, sizeof(__u64));

	if ( !pumem->frame_addrs ) 
		return -1;

	pumem->frame_cnt = NUM_FRAMES;
	pumem->head = NUM_FRAMES;

	for (uint32_t i = 0 ; i < NUM_FRAMES; i++)
		pumem->frame_addrs[i] = xsk_umem_frame_addr(i);

	return 0;
}

// UMEM 생성 함수
int xsk_configure_umem(struct xsk_umem_info *pumem)
{
	int i = 0; 
	int ret = 0;
	int num = 0;
	void *buffer = NULL;

	__u32 idx = 0;

	struct xsk_umem_config cfg = {
		.fill_size = RX_RING_SZ,
		.comp_size = TX_RING_SZ,
		.frame_size = FRAME_SIZE,
		.frame_headroom = 0,
		.flags = 0,
	};

	if (posix_memalign(&buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) 
	{
		perror("posix_memalign");
		return -1;
	}

	memset(buffer, 0, NUM_FRAMES * FRAME_SIZE);

	ret = xsk_umem__create(&pumem->umem, buffer, NUM_FRAMES * FRAME_SIZE,
			&pumem->fq, &pumem->cq, &cfg);
	if (ret) 
	{
		fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret));
		free(buffer);
		return -1;
	}

	pumem->buffer = buffer;
	pumem->buffer_len = NUM_FRAMES * FRAME_SIZE;

	if (xsk_frame_pool_init(pumem)) 
	{
		fprintf(stderr, "uframe_pool_init failed\n");
		return -1;
	}

	// RX용Fill Ring 초기화: UMEM의 일부 프레임을 커널에 제공
	idx = 0;
	num = xsk_ring_prod__reserve(&pumem->fq, RX_RING_SZ, &idx);

	if (num > 0) 
	{
		for (i = 0; i < num; i++) 
		{
			__u64 addr = xsk_frame_alloc(pumem);

			if ( addr == (__u64)-1 ) 
			{
				// 부족하면 남은 것만 채워 제출
				num = i;
				break;
			}
			*xsk_ring_prod__fill_addr(&pumem->fq, idx + i) = addr;
		}
		xsk_ring_prod__submit(&pumem->fq, num);
	}

	return 0;
}

// Socket 생성 함수
int xsk_configure_socket(struct xsk_socket_info *psock)
{
	int ret = 0;

	struct xsk_socket_config cfg = {
		.rx_size = RX_RING_SZ,
		.tx_size = TX_RING_SZ,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags    = XDP_FLAGS_SKB_MODE,   // SKB 모드 
		.bind_flags   = XDP_COPY | XDP_USE_NEED_WAKEUP,
	};

	ret = xsk_socket__create(&psock->xsk, psock->ifname, psock->queue_id,
			psock->umem.umem, &psock->rx, &psock->tx, &cfg);
	if ( ret ) 
	{
		fprintf(stderr, "xsk_socket__create(%s,q%u): %s\n",
				psock->ifname, psock->queue_id, strerror(-ret));

		return -1;
	}

	psock->xsk_fd = xsk_socket__fd(psock->xsk);

	return 0;
}

// 소켓 및 UMEM 자원 정리 함수
void xsk_socket_cleanup(struct xsk_socket_info *xsk) 
{
	if ( !xsk ) 
		return;

	if ( xsk->xsk) 
		xsk_socket__delete(xsk->xsk);

	if (xsk->umem.umem)
		xsk_umem__delete(xsk->umem.umem);

	if (xsk->umem.buffer)
		free(xsk->umem.buffer);

	//free(xsk->umem.umem);
}

// Comp Ring 프래임 정리 함수
void xsk_recycle_tx_completions(struct xsk_umem_info *pumem)
{
	// TX 완료된 프레임 주소를 CQ에서 꺼내 free stack으로 반환
	__u32 idx;
	__u64 addr;
	unsigned int i = 0;
	unsigned int rcvd = 0;

	while ( (rcvd = xsk_ring_cons__peek(&pumem->cq, BATCH, &idx)) > 0 ) 
	{
		for ( i = 0; i < rcvd; i++ ) 
		{
			addr = *xsk_ring_cons__comp_addr(&pumem->cq, idx + i);
			xsk_frame_free(pumem, addr);
		}
		xsk_ring_cons__release(&pumem->cq, rcvd);
	}
}

// Fill Ring 프래임 전체 재할당 함수
void xsk_topup_fill_ring(struct xsk_umem_info *pumem)
{

	// RX fill ring이 비지 않도록 free stack에서 보충
	__u32 idx = 0;
	__u64 addr = 0;

	int i = 0;
	int ret = 0;
	int can = 0;
	int to_submit = 0;

	can = xsk_prod_nb_free(&pumem->fq, RX_RING_SZ);
	if ( can <= 0 ) 
		return;

	ret = xsk_ring_prod__reserve(&pumem->fq, can, &idx);
	if ( ret != can ) 
	{
		/* 예약 실패 시 포기 */
		return;
	}

	for ( i = 0; i < can; i++ ) 
	{
		addr = xsk_frame_alloc(pumem);

		if (addr == (__u64)-1) 
			break;

		*xsk_ring_prod__fill_addr(&pumem->fq, idx + i) = addr;

		to_submit++;
	}

	if ( to_submit )
		xsk_ring_prod__submit(&pumem->fq, to_submit);
}

// Fill Ring 프래임 재할당 함수
void xsk_recycle_fill_ring( struct xsk_socket_info *sock, __u64 addr )
{
	__u32 idx_f = 0;

	if (!sock) 
		return;

	if (addr == 0) 
		return; // 이중 재활용 가드(선택)

	if (xsk_ring_prod__reserve(&sock->umem.fq, 1, &idx_f) == 1) 
	{
		*xsk_ring_prod__fill_addr(&sock->umem.fq, idx_f) = addr;
		xsk_ring_prod__submit(&sock->umem.fq, 1);
	} else {
		xsk_frame_free(&sock->umem, addr);
	}

}


/* 필요시 커널을 깨워 TX kick */
void xsk_kick_tx_if_needed(struct xsk_socket_info *psock)
{
	if ( xsk_ring_prod__needs_wakeup(&psock->tx) ) 
	{
		/* sendto(…MSG_DONTWAIT)로 kick */
		sendto(psock->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	}
}
