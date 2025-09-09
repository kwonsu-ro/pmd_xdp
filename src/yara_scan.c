#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <errno.h>

#include "yara_scan.h"

// -----------------------------------------
// 워커 컨텍스트
// -----------------------------------------
typedef struct _yara_worker_ctx 
{
    YR_SCANNER *scanner;
    int id;
} YARA_WORKER_CTX;


char yara_rule_path[256] = {0}; // YARA Rule 파일

YR_RULES *rules = NULL;                 // 읽기 전용 공유

static YARA_JOB_QUEUE g_q;
static pthread_t *g_workers = NULL;
static YARA_WORKER_CTX *g_wctx = NULL;
static int g_worker_cnt = 0;


// -----------------------------------------
// 콜백: 첫 매칭 즉시 중단
// -----------------------------------------
static int yara_callback_quick(YR_SCAN_CONTEXT *ctx, int msg, void *msg_data, void *user_data) 
{
    if (msg == CALLBACK_MSG_RULE_MATCHING) 
    {
        *(int *)user_data = 1;

        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

static void q_init(YARA_JOB_QUEUE *q) 
{
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->m, NULL);
    pthread_cond_init(&q->cv_not_empty, NULL);
    pthread_cond_init(&q->cv_not_full, NULL);
}

static void q_fini(YARA_JOB_QUEUE *q) 
{
    pthread_mutex_destroy(&q->m);
    pthread_cond_destroy(&q->cv_not_empty);
    pthread_cond_destroy(&q->cv_not_full);
}

static void q_push(YARA_JOB_QUEUE *q, const YARA_SCAN_JOB *job) 
{
    pthread_mutex_lock(&q->m);

    while (!q->stop && q->count == YARA_SCAN_QCAP) 
    {
        pthread_cond_wait(&q->cv_not_full, &q->m);
    }

    if (!q->stop) 
    {
        q->ring[q->tail] = *job;
        q->tail = (q->tail + 1) % YARA_SCAN_QCAP;
        q->count++;
        pthread_cond_signal(&q->cv_not_empty); // ← 워커를 깨우는 신호
    }

    pthread_mutex_unlock(&q->m);
}

static int q_pop(YARA_JOB_QUEUE *q, YARA_SCAN_JOB *out) 
{
    pthread_mutex_lock(&q->m);

    while (!q->stop && q->count == 0) 
    {
        pthread_cond_wait(&q->cv_not_empty, &q->m);
    }

    if (q->count == 0 && q->stop) 
    {
        pthread_mutex_unlock(&q->m);

        return 0;
    }

    *out = q->ring[q->head];
    q->head = (q->head + 1) % YARA_SCAN_QCAP;
    q->count--;
    pthread_cond_signal(&q->cv_not_full); // 생산자를 깨우는 신호(가득 참 해제)
    pthread_mutex_unlock(&q->m);

    return 1;
}

// -----------------------------------------
// 워커 메인
// -----------------------------------------
static void *worker_main(void *arg) 
{
	int match = 0;
    YARA_SCAN_JOB job;
    YARA_WORKER_CTX *w = (YARA_WORKER_CTX *)arg;

    if ( !w->scanner ) 
    {
        if ( !rules )
		return NULL;

        if ( yr_scanner_create(rules, &w->scanner) != ERROR_SUCCESS) 
	{
            fprintf(stderr, "[YARA] 워커 %d: 스캐너 생성 실패\n", w->id);
            return NULL;
        }

        yr_scanner_set_flags(w->scanner, SCAN_FLAGS_FAST_MODE);
        yr_scanner_set_timeout(w->scanner, YARA_TIMEOUT_MS);
    }

    while ( q_pop(&g_q, &job) && !g_q.stop )
    {
        match = 0;
        if (job.buf && job.len && w->scanner) 
	{
            yr_scanner_set_callback(w->scanner, yara_callback_quick, &match);
            (void)yr_scanner_scan_mem(w->scanner, job.buf, job.len);
        }

        if (job.done) 
		job.done(match, job.user);

        if ( job.out_match && job.sync_m && job.sync_cv && job.sync_done ) 
	{
            *job.out_match = match;
            pthread_mutex_lock(job.sync_m);
            *job.sync_done = 1;
            pthread_cond_signal(job.sync_cv);
            pthread_mutex_unlock(job.sync_m);
        }
    }

    return NULL;
}

// -----------------------------------------
// 공개 API: 초기화/종료(호환)
// -----------------------------------------
int yara_init(const char *rule_path) 
{
    int ret = 0;

    if (!rule_path || !rule_path[0]) 
    {
        fprintf(stderr, "[YARA] 잘못된 룰 경로입니다.\n");
        return -1;
    }

    snprintf(yara_rule_path, sizeof(yara_rule_path), "%s", rule_path);

    ret = yr_initialize();
    if (ret != ERROR_SUCCESS) 
    {
        fprintf(stderr, "[YARA] 라이브러리 초기화 실패(%d)\n", ret);
        return -1;
    }

    if (rules) 
    {
        yr_rules_destroy(rules);
        rules = NULL;
    }

    printf("[YARA] 규칙 로드: %s\n", yara_rule_path);
    ret = yr_rules_load(yara_rule_path, &rules);

    if (ret != ERROR_SUCCESS || !rules) 
    {
        fprintf(stderr, "[YARA] 규칙 로드 실패(%d): %s\n", ret, yara_rule_path);
        yr_finalize();
        return -1;
    }

    printf("[YARA] 초기화 완료 (FAST_MODE, timeout=%dms)\n", YARA_TIMEOUT_MS);

    return 0;
}

void yara_finalize(void) 
{
    if (rules) 
    {
        yr_rules_destroy(rules);
        rules = NULL;
    }

    yr_finalize();
}

// -----------------------------------------
// 공개 API: 워커 풀 시작/중지
// -----------------------------------------
int yara_workers_start(int n_workers) 
{
    if (n_workers <= 0) 
	    return -1;

    if (!rules) 
    {
        fprintf(stderr, "[YARA] rules가 초기화되지 않았습니다.\n");
        return -1;
    }

    if (g_workers) 
	  return 0; // 이미 실행 중

    q_init(&g_q);

    g_worker_cnt = n_workers;
    g_workers = (pthread_t *)calloc((size_t)n_workers, sizeof(pthread_t));
    g_wctx = (YARA_WORKER_CTX *)calloc((size_t)n_workers, sizeof(YARA_WORKER_CTX));
    if (!g_workers || !g_wctx)
	   return -1;

    for (int i = 0; i < n_workers; i++)
    {
        g_wctx[i].scanner = NULL;
        g_wctx[i].id = i;

        if (pthread_create(&g_workers[i], NULL, worker_main, &g_wctx[i]) != 0) 
	{
            fprintf(stderr, "[YARA] 워커 %d 생성 실패\n", i);
            g_worker_cnt = i;
            return -1;
        }
    }
    return 0;
}

void yara_workers_stop(void) 
{
    pthread_mutex_lock(&g_q.m);
    g_q.stop = 1;
    pthread_cond_broadcast(&g_q.cv_not_empty);
    pthread_cond_broadcast(&g_q.cv_not_full);
    pthread_mutex_unlock(&g_q.m);

    // 3) 워커 조인
    for (int i = 0; i < g_worker_cnt; i++) 
    {
	    pthread_join(g_workers[i], NULL);
	    if (g_wctx[i].scanner) 
	    {
		    yr_scanner_destroy(g_wctx[i].scanner);
		    g_wctx[i].scanner = NULL;
	    }
    }

    free(g_workers); 
    g_workers = NULL;

    free(g_wctx); 
    g_wctx = NULL;

    g_worker_cnt = 0;

    q_fini(&g_q);
}

// -----------------------------------------
// 공개 API: 비동기 제출(제로카피)
// - payload 버퍼는 콜백이 끝날 때까지 유효해야 합니다.
// -----------------------------------------
int yara_submit(const uint8_t *payload, size_t len,
                     YARA_SCAN_DONE_CB cb, void *user) 
{
    if (!payload || len == 0)
	    return 0;

    if (!g_workers || g_worker_cnt <= 0)
	    return -1;

    YARA_SCAN_JOB job = {
        .buf = payload,
        .len = len,
        .done = cb,
        .user = user,
        .out_match = NULL,
        .sync_m = NULL, .sync_cv = NULL, .sync_done = NULL
    };

    q_push(&g_q, &job);

    return 0;
}

// -----------------------------------------
// 공개 API: 동기 제출(완료까지 대기)
// -----------------------------------------
int yara_submit_sync(const uint8_t *payload, size_t len, int *out_match) 
{
    int done = 0;
    int match = 0;

    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;

    if (!payload || len == 0) 
    { 
	   if (out_match) 
		   *out_match = 0; 
	   
	   return 0; 
    }

    if (!g_workers || g_worker_cnt <= 0) 
	    return -1;

    YARA_SCAN_JOB job = {
        .buf = payload,
        .len = len,
        .done = NULL,
        .user = NULL,
        .out_match = &match,
        .sync_m = &m, .sync_cv = &cv, .sync_done = &done
    };

    pthread_mutex_lock(&m);
    q_push(&g_q, &job);

    while (!done) 
    {
        pthread_cond_wait(&cv, &m);
    }

    pthread_mutex_unlock(&m);

    if (out_match) 
	    *out_match = match;

    return 0;
}

// -----------------------------------------
// 호환용: 직접 호출 스캔(원하면 사용)
// -----------------------------------------
int yara_scan_packet(const uint8_t *data, size_t len) 
{
    int match = 0;
    static __thread YR_SCANNER *tls_scanner = NULL;

    if (!data || len == 0) 
	    return 0;
    if (rules == NULL) 
	    return 0;

    if ( !tls_scanner ) 
    {
        if (yr_scanner_create(rules, &tls_scanner) != ERROR_SUCCESS) 
	{
            fprintf(stderr, "[YARA] 스캐너 생성 실패\n");
            return 0;
        }

        yr_scanner_set_flags(tls_scanner, SCAN_FLAGS_FAST_MODE);
        yr_scanner_set_timeout(tls_scanner, YARA_TIMEOUT_MS);
    }

    yr_scanner_set_callback(tls_scanner, yara_callback_quick, &match);
    (void)yr_scanner_scan_mem(tls_scanner, data, len);

    return match;
}

// -----------------------------------------
// 선택: 수동 재로딩
// -----------------------------------------
int yara_reload(void) 
{
    int ret = 0;

    if (yara_rule_path[0] == '\0') 
	    return -1;

    if (rules) 
    { 
	    yr_rules_destroy(rules); 
	    rules = NULL; 
    }

    ret = yr_rules_load(yara_rule_path, &rules);

    if (ret != ERROR_SUCCESS || !rules) 
    {
        fprintf(stderr, "[YARA] 규칙 재로딩 실패(%d): %s\n", ret, yara_rule_path);
        return -1;
    }

    printf("[YARA] 규칙 재로딩 성공: %s\n", yara_rule_path);

    return 0;
}
