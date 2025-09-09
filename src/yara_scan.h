#ifndef YARA_SCAN_H
#define YARA_SCAN_H

#include <stddef.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <yara.h>

#define YARA_SCAN_QCAP  32767        // 작업 큐 용량

enum { 
	YARA_TIMEOUT_MS = 20 
}; // 20~50ms 권장

// -----------------------------------------
// 작업 정의(제로카피 제출)
// - 주의: buf는 워커가 처리 완료할 때까지 유효해야 합니다.
// -----------------------------------------
typedef void (*YARA_SCAN_DONE_CB)(int match, void *user);

typedef struct _yara_scan_job 
{
    const uint8_t *buf;
    size_t len;
    YARA_SCAN_DONE_CB done;
    void *user;

    // 동기 제출용
    int *out_match;
    pthread_mutex_t *sync_m;

    pthread_cond_t  *sync_cv;
    int *sync_done;
} YARA_SCAN_JOB;


// -----------------------------------------
// 고정 길이 원형 큐
// -----------------------------------------
typedef struct _yara_job_queue {
    YARA_SCAN_JOB ring[YARA_SCAN_QCAP];
    size_t head, tail, count;
    pthread_mutex_t m;
    
    // “큐가 비어 있지 않다”를 알리는 조건변수(워커 깨움)
    pthread_cond_t cv_not_empty;

    // “큐가 가득 차지 않았다”를 알리는 조건변수(생산자 깨움)
    pthread_cond_t cv_not_full;
    int stop;
} YARA_JOB_QUEUE;

typedef struct _yara_job_ctx {
    // 패킷/버퍼 메타데이터
    __u64 rx_addr;                 // AF_XDP 등의 RX descriptor 주소(재활용 시 필요)
    char *buffer;                  // 로깅용 문자열(옵션)
    void *rx_data;
    __u32 rx_len;

    // 블록리스트 업데이트에 필요한 정보
    int blocklist_fd;              // bpf_map fd
    __u64 flow_id;                 // make_flow_id로 계산한 flow key
    __u8  bl_val;                  // 블록리스트 값(보통 1)
    time_t expire_ts;
    uint32_t ifindex;  // 해당 NIC의 ifindex 저장

    // 환경/함수 포인터(필요 시)
    void *rxp;                     // recycle_fill_ring 호출 시 필요한 컨텍스트
    unsigned int *consumed_rx;

} YARA_JOB_CTX;


// -----------------------------------------
// 공개 API: 초기화/종료(호환)
// -----------------------------------------
int yara_init(const char *rule_path); 

void yara_finalize(void); 

// -----------------------------------------
// 공개 API: 워커 풀 시작/중지
// -----------------------------------------
int yara_workers_start(int n_workers);

void yara_workers_stop(void);

// -----------------------------------------
// 공개 API: 비동기 제출(제로카피)
// - payload 버퍼는 콜백이 끝날 때까지 유효해야 합니다.
// -----------------------------------------
int yara_submit(const uint8_t *payload, size_t len,
                     YARA_SCAN_DONE_CB cb, void *user);

// -----------------------------------------
// 공개 API: 동기 제출(완료까지 대기)
// -----------------------------------------
int yara_submit_sync(const uint8_t *payload, size_t len, int *out_match);

// -----------------------------------------
// 호환용: 직접 호출 스캔(원하면 사용)
// -----------------------------------------
int yara_scan_packet(const uint8_t *data, size_t len);

// -----------------------------------------
// 선택: 수동 재로딩
// -----------------------------------------
int yara_reload(void);

#endif
