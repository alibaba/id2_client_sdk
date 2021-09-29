/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "ls_osa.h"
#include "ls_osa_list.h"

#define LS_PMGR_MAGIC        0x506F4F6C

#define ROUND_UP(_v, _a)     (((ulong_t)(_v) + (_a) - 1) & (~((_a) - 1)))
#define IS_ALIGNED(_v, _a)   (!((ulong_t)(_v) & ((_a) - 1)))

/* reserved for memory pool */
static uint8_t g_rsvd_mem[4096] = {0};

static void *g_pmgr_handle = NULL;

typedef struct _ls_mem_blk_t {
    void *addr;
    uint32_t size;
    ls_osa_list_t node;
} ls_mem_blk_t;

typedef struct _ls_pool_mgr_t {
   uint32_t magic;
   uint32_t size;
   void *start;
   ls_osa_list_t used;
} ls_pool_mgr_t;

static void *_create_pmgr_handle(void *start, uint32_t size)
{
    uint32_t align = sizeof(void *);
    ls_pool_mgr_t *pmgr = NULL;

    if (!IS_ALIGNED(start, align)) {
        ls_osa_print("start(0x%x) is not aligned\n", (ulong_t)start);
        return NULL;
    }

    if (size < sizeof(ls_pool_mgr_t) + sizeof(ls_mem_blk_t)) {
        ls_osa_print("size(%s) is too small\n", size);
        return NULL;
    }

    pmgr = (ls_pool_mgr_t *)start;
    pmgr->start = (void *)((ulong_t)start + sizeof(ls_pool_mgr_t));
    pmgr->size = size - sizeof(ls_pool_mgr_t);
    ls_osa_list_init(&pmgr->used);
    pmgr->magic = LS_PMGR_MAGIC;

#ifdef CONFIG_OSA_DEBUG
    ls_osa_print("osa mem pool -- start: 0x%x  size:0x%x\n", (ulong_t)pmgr->start, size);
#endif

    return (void *)pmgr;
}

static void _destroy_pmgr_handle(void *handle)
{
    ls_pool_mgr_t *pmgr = (ls_pool_mgr_t *)handle;

    if (!pmgr || pmgr->magic != LS_PMGR_MAGIC) {
        return;
    }

    memset(pmgr, 0, sizeof(ls_pool_mgr_t));

    return;
}

static void *_alloc_mem_blk(void *handle, uint32_t size)
{
    void *addr = NULL;
    ls_pool_mgr_t *pmgr;
    ls_osa_list_t *entry, *next;
    ls_mem_blk_t *bk_new, *bk_cur, *bk_next;

    pmgr = (ls_pool_mgr_t *)handle;
    if (!pmgr || pmgr->magic != LS_PMGR_MAGIC) {
        ls_osa_print("pmgr handle is invalid\n");
        return NULL;
    }

    size = ROUND_UP(size, sizeof(void *));
    size += sizeof(ls_mem_blk_t);

    if (ls_osa_list_empty(&pmgr->used)) {
        if (size <= pmgr->size) {
            bk_new = (ls_mem_blk_t *)pmgr->start;
            bk_new->addr = pmgr->start;
            bk_new->size = size;
            ls_osa_list_add_tail(&pmgr->used, &bk_new->node);
            addr = (void *)((ulong_t)bk_new->addr + sizeof(ls_mem_blk_t));
            goto _out;
        } else {
            ls_osa_print("mem blk not be allocated\n");
            addr = NULL;
            goto _out;
        }
    } else {
        entry = pmgr->used.next;
        bk_cur = ls_osa_list_entry(entry, ls_mem_blk_t, node);
        if (size <= (ulong_t)bk_cur->addr - (ulong_t)pmgr->start) {
            bk_new = (ls_mem_blk_t *)pmgr->start;
            bk_new->addr = pmgr->start;
            bk_new->size = size;
            ls_osa_list_add(&pmgr->used, &bk_new->node);
            addr = (void *)((ulong_t)bk_new->addr + sizeof(ls_mem_blk_t));
            goto _out;
        }

        ls_osa_list_iterate_safe(&pmgr->used, entry, next) {
            bk_cur = ls_osa_list_entry(entry, ls_mem_blk_t, node);

            if (next == &pmgr->used) {
                addr = (void *)((ulong_t)pmgr->start + pmgr->size);
            } else {
                bk_next = ls_osa_list_entry(next, ls_mem_blk_t, node);
                addr = bk_next->addr;
            }

            if (size <= (ulong_t)addr - ((ulong_t)bk_cur->addr + bk_cur->size)) {
                bk_new = (ls_mem_blk_t *)((ulong_t)bk_cur->addr + bk_cur->size);
                bk_new->addr = (void *)bk_new;
                bk_new->size = size;
                ls_osa_list_add(entry, &bk_new->node);
                addr = (void *)((ulong_t)bk_new->addr + sizeof(ls_mem_blk_t));
                break;
            } else {
                if (next == &pmgr->used) {
                    ls_osa_print("mem blk not be allocated\n");
                    addr = NULL;
                    goto _out;
                }
            }
        }
    }

_out:
#ifdef CONFIG_OSA_DEBUG
    if (addr != NULL) {
        ls_osa_print("osa mem alloc -- addr: 0x%x 0x%x  size: 0x%x\n", (ulong_t)addr - sizeof(ls_mem_blk_t), (ulong_t)addr, size);
    }
#endif

    return addr;
}

static void _free_mem_blk(void *handle, void *addr)
{
    ls_pool_mgr_t *pmgr;
    ls_mem_blk_t *bk_node;
    ls_osa_list_t *entry, *tmp;

    pmgr = (ls_pool_mgr_t *)handle;
    if (!pmgr || pmgr->magic != LS_PMGR_MAGIC) {
        return;
    }

    if (addr == NULL) {
        return;
    }

    if (!IS_ALIGNED(addr, sizeof(void *))) {
        ls_osa_print("freed addr(0x%x) is not aligned\n", (ulong_t)addr);
        return;
    }

    ls_osa_list_iterate_safe(&pmgr->used, entry, tmp) {
        bk_node = ls_osa_list_entry(entry, ls_mem_blk_t, node);
        if ((ulong_t)addr == (ulong_t)bk_node->addr + sizeof(ls_mem_blk_t)) {
            bk_node->addr = NULL;
            bk_node->size = 0;
            ls_osa_list_del(&bk_node->node);
            break;
        }
    }

    if (ls_osa_list_empty(&pmgr->used)) {
        _destroy_pmgr_handle(handle);
        g_pmgr_handle = NULL;
    }

#ifdef CONFIG_OSA_DEBUG
    ls_osa_print("osa mem free -- addr: 0x%x 0x%x\n", (ulong_t)addr - sizeof(ls_mem_blk_t), (ulong_t)addr);
#endif

    return;
}

void ls_osa_print(const char *fmt, ...)
{
    va_list va_args;

    va_start(va_args, fmt);

    printf(LS_LOG_TAG);

    vprintf(fmt, va_args);

    va_end(va_args);
}

int ls_osa_snprintf(char *str, size_t size, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, size, fmt, args);
    va_end(args);

    return rc;
}

void *ls_osa_malloc(size_t size)
{
    if (g_pmgr_handle == NULL) {
        g_pmgr_handle = _create_pmgr_handle(g_rsvd_mem, sizeof(g_rsvd_mem)/sizeof(uint8_t));
        if (g_pmgr_handle == NULL) {
            return NULL;
        }
    }

    return _alloc_mem_blk(g_pmgr_handle, size);
}

void *ls_osa_calloc(size_t nmemb, size_t size)
{
    void *buf = NULL;

    if (nmemb == 0 || size == 0) {
        return NULL;
    }

    buf = ls_osa_malloc(nmemb * size);
    if (buf != NULL) {
        memset(buf, 0, nmemb * size);
    }

    return buf;
}

void ls_osa_free(void *ptr)
{
    return _free_mem_blk(g_pmgr_handle, ptr);
}

void ls_osa_msleep(unsigned int msec)
{
    usleep(msec * 1000);
}

long long ls_osa_get_time_ms(void)
{
    struct timeval tv;
    long long ret = 0;

    gettimeofday(&tv, NULL);
    ret = tv.tv_sec * (1000LL) + tv.tv_usec / (1000LL);

    return ret;
}

int ls_osa_mutex_create(void **mutex)
{
    return -1;
}

void ls_osa_mutex_destroy(void *mutex)
{
    return;
}

int ls_osa_mutex_lock(void *mutex)
{
    return -1;
}

int ls_osa_mutex_unlock(void *mutex)
{
    return -1;
}

int ls_osa_net_connect(const char *host, const char *port, int type)
{
    return -1;
}

void ls_osa_net_disconnect(int fd)
{
    return;
}

int ls_osa_net_send(int fd, unsigned char *buf, size_t len, int *ret_orig)
{
    return -1;
}

int ls_osa_net_recv(int fd, unsigned char *buf, size_t len, int timeout, int *ret_orig)
{
    return -1;
}


