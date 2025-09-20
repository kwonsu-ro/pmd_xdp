// af_xdp_util.h 헤더
#ifndef XDP_UTIL_H
#define XDP_UTIL_H

#include <stdint.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include <sys/ioctl.h>
#include <net/if.h>

#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define NUM_FRAMES      32767
#define RX_RING_SZ      16384
#define TX_RING_SZ      16384
#define BATCH           4096
#define MAX_BUFF        1024

/* ====== UMEM/프레임 풀 ====== */
struct xsk_umem_info {
    void               *buffer;
    size_t              buffer_len;
    struct xsk_umem    *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;

    /* 간단한 프레임 풀 (TX에 사용) */
    __u64              *frame_addrs;
    uint32_t            frame_cnt;
    uint32_t            head; /* free stack top */
};

struct xsk_socket_info {
    char ifname[IFNAMSIZ];
    uint32_t            ifindex;
    uint32_t            queue_id;

    /* per-IF UMEM */
    struct xsk_umem_info    umem;

    /* XSK */
    struct xsk_socket  *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    int                 xsk_fd;

    /* XDP 프로그램 & xsks_map */
    struct xdp_program *xdp_prog;
    int                 xsks_map_fd;

    /* MAC 제어 */
    unsigned char       if_mac[ETH_ALEN];   /* 본인 NIC MAC */
    int blocklist_fd;

};

// 전송 프레임을 UMEM에서 하나 해제하는 함수
void xsk_frame_free(struct xsk_umem_info *pumem, __u64 addr);

// 전송 프레임을 UMEM에서 하나 할당하는 함수
__u64 xsk_frame_alloc(struct xsk_umem_info *tmp);


// UMEM 설정 함수
int xsk_configure_umem(struct xsk_umem_info *tmp);

// AF_XDP 소켓 설정 함수
int xsk_configure_socket(struct xsk_socket_info *psock);

// AF_XDP 소켓 정리 함수
void xsk_socket_cleanup(struct xsk_socket_info *xsk);

// Comp Ring 재사용
void xsk_recycle_tx_completions(struct xsk_umem_info *pumem);

void xsk_topup_fill_ring(struct xsk_umem_info *pumem);

void xsk_recycle_fill_ring( struct xsk_socket_info *sock, __u64 addr );

void xsk_kick_tx_if_needed(struct xsk_socket_info *psock);

#endif /* AF_XDP_UTIL_H */
