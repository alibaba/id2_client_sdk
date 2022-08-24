/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#include "ls_osa.h"

#if defined(__DEMO__)

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>

#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#if defined(CONFIG_LS_OS_ANDROID)
#include <android/log.h>
#endif

typedef struct __ls_thread_t {
    pthread_t        tid;
} _ls_thread_t;

void ls_osa_print(const char *fmt, ...)
{
    va_list va_args;

    va_start(va_args, fmt);

#if defined(CONFIG_LS_OS_ANDROID)
    __android_log_vprint(
              ANDROID_LOG_INFO,
              LS_LOG_TAG,
              fmt, va_args);
#else
    printf(LS_LOG_TAG);
    vprintf(fmt, va_args);
#endif

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
    return malloc(size);
}

void *ls_osa_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void ls_osa_free(void *ptr)
{
    free(ptr);
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
    if (mutex == NULL) {
        return -1;
    }
    *mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!*mutex) {
        return -1;
    }

    return pthread_mutex_init(*mutex, NULL);
}

void ls_osa_mutex_destroy(void *mutex)
{
    if (mutex == NULL) {
        return;
    }

    pthread_mutex_destroy(mutex);
    if (mutex) {
        free(mutex);
        mutex = NULL;
    }
}

int ls_osa_mutex_lock(void *mutex)
{
    return pthread_mutex_lock(mutex);
}

int ls_osa_mutex_unlock(void *mutex)
{
    return pthread_mutex_unlock(mutex);
}

int ls_osa_net_connect(const char *host, const char *port, int type)
{
    int fd = -1;
    int ret = 0;
    struct addrinfo hints, *addr_list, *cur;

    /* do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type == LS_NET_TYPE_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = type == LS_NET_TYPE_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if ((ret = getaddrinfo(host, port, &hints, &addr_list)) != 0) {
        ls_osa_print("getaddrinfo fail, errno: %d, %d\n", errno, ret);
        return -1;
    }

    /* try the sockaddrs until a connection succeeds */
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        fd = (int)socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            continue;
        }

       do {
            if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
                goto _out;
            } else {
                if (errno == EINTR) {
                    continue;
                }

                break;
            }
        } while (1);

        close(fd);
        fd = -1;
    }

_out:
    freeaddrinfo(addr_list);

    return fd;
}

void ls_osa_net_disconnect(int fd)
{
    if (fd < 0) {
        return;
    }

    shutdown(fd, 2);
    close(fd);

    return;
}

int ls_osa_net_send(int fd, unsigned char *buf, size_t len, int *ret_orig)
{
    int ret;

    if (fd < 0 || ret_orig == NULL) {
        ls_osa_print("net_send: invalid args\n");
        return -1;
    }

    *ret_orig = 0;

    ret = (int)write(fd, buf, len);
    if (ret < 0) {
        if (errno == EINTR) {
            *ret_orig = -1;
        }
    }

    return ret;
}

int ls_osa_net_recv(int fd, unsigned char *buf, size_t len, int timeout, int *ret_orig)
{
    int ret;
    struct timeval tv;
    fd_set read_fds;

    if (fd < 0 || timeout < 0 || ret_orig == NULL) {
        ls_osa_print("net_recv: invalid args\n");
        return -1;
    }

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    ret = select(fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv);
    if (ret == 0) {
        /* timeout */
        *ret_orig = -2;
        return -1;
    }

    if (ret < 0) {
        if (errno == EINTR) {
            *ret_orig = -1;
        }

        return -1;
    }

    ret = (int)read(fd, buf, len);
    if (ret < 0) {
        if (errno == EINTR) {
            *ret_orig = -1;
        }

        return -1;
    }

    return ret;
}

ls_osa_sem_t ls_osa_sem_create(uint32_t init_val)
{
    int32_t ret;
    sem_t *sem = NULL;

    sem = (sem_t *)ls_osa_malloc(sizeof(sem_t));
    if (NULL == sem) {
        ls_osa_print("out of mem, %d\n", (uint32_t)sizeof(sem_t));
        return NULL;
    }

    ret = sem_init(sem, 0, init_val);
    if (ret != 0) {
        ls_osa_print("sem init fail - errno: %d\n", errno);
        ls_osa_free(sem);
        return NULL;
    }

    return (ls_osa_sem_t)sem;
}

void ls_osa_sem_destroy(ls_osa_sem_t sem)
{
    if (sem == NULL) {
        return;
    }

    ls_osa_free(sem);
}

int ls_osa_sem_wait(ls_osa_sem_t sem, uint32_t time_ms)
{
    int32_t ret;
    struct timespec ts;

    if (sem == NULL) {
        ls_osa_print("sem is null\n");
        return -1;
    }

    if (LS_TIME_INFINITE == time_ms) {
        sem_wait(sem);
        ret = 0;
    } else if (0 == time_ms) {
        ret = sem_trywait(sem);
    } else {
        ts.tv_sec = time(NULL) + time_ms / 1000;
        ts.tv_nsec = (time_ms % 1000) * 1000;

        while ((ret = sem_timedwait(sem, &ts)) == -1 && errno == EINTR) {
            continue;
        }
    }

    if (0 != ret) {
        if (ETIMEDOUT == errno) {
            ls_osa_print("wait sem timeout\n");
            return -1;
        } else {
            ls_osa_print("unknown err in waiting sem, %d", errno);
            return -2;
        }
    }

    return 0;
}

void ls_osa_sem_post(ls_osa_sem_t sem)
{
    if (sem == NULL) {
        ls_osa_print("sem is null\n");
        return;
    }

    sem_post(sem);
}

ls_osa_thread_t ls_osa_thread_create(const char *name,
                      void(*func)(void *), void *arg, size_t stack_size)
{
    int32_t ret;
    size_t retry = 0;
    _ls_thread_t *thrd = NULL;

    if (func == NULL) {
        ls_osa_print("invaid input arg\n");
        return NULL;
    }

    thrd = ls_osa_malloc(sizeof(_ls_thread_t));
    if (NULL == thrd) {
        ls_osa_print("out of mem, %d\n", (uint32_t)sizeof(_ls_thread_t));
        return NULL;
    } else {
        memset(thrd, 0, sizeof(_ls_thread_t));
    }

    if (name != NULL) {
        if (strlen(name) > 16) {
            ls_osa_print("invalid name length: %d\n", (uint32_t)strlen(name));
            ret = -1;
            goto _err;
        }

        prctl(PR_SET_NAME, name);
    } else {
        prctl(PR_SET_NAME, "ls_osa_thrd");
    }

    do {
        errno = 0;
        ret = pthread_create(&thrd->tid, NULL, (void *(*)(void *))func, arg);
        if (ret != 0 && (errno != EAGAIN || retry++ > 10)) {
            ls_osa_print("pthread create fail, %d\n", ret);
            goto _err;
        }
    } while(ret != 0);

_err:
    if (ret != 0) {
       if (thrd != NULL) {
           ls_osa_free(thrd);
       }

       thrd = NULL;
    }

    return (ls_osa_thread_t)thrd;
}

void ls_osa_thread_destroy(ls_osa_thread_t thread)
{
    int32_t ret;
    _ls_thread_t *thrd;

    if (thread == NULL) {
        return;
    }

    thrd = (_ls_thread_t *)thread;

    ret = pthread_join(thrd->tid, NULL);
    if (ret != 0) {
        ls_osa_print("pthread join fail, %d\n", ret);
    }

    ls_osa_free(thrd);

    return;
}

#else  /* __DEMO__ */

void ls_osa_print(const char *fmt, ...)
{
    return;
}

int ls_osa_snprintf(char *str, size_t size, const char *fmt, ...)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

void *ls_osa_malloc(size_t size)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return NULL;
}

void *ls_osa_calloc(size_t nmemb, size_t size)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return NULL;
}

void ls_osa_free(void *ptr)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

void ls_osa_msleep(unsigned int msec)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

long long ls_osa_get_time_ms(void)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return 0;
}

int ls_osa_mutex_create(void **mutex)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

void ls_osa_mutex_destroy(void *mutex)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

int ls_osa_mutex_lock(void *mutex)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_osa_mutex_unlock(void *mutex)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_osa_net_connect(const char *host, const char *port, int type)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

void ls_osa_net_disconnect(int fd)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

int ls_osa_net_send(int fd, unsigned char *buf, size_t len, int *ret_orig)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_osa_net_recv(int fd, unsigned char *buf, size_t len, int timeout, int *ret_orig)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

ls_osa_sem_t ls_osa_sem_create(uint32_t init_val)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return NULL;
}

void ls_osa_sem_destroy(ls_osa_sem_t sem)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

int ls_osa_sem_wait(ls_osa_sem_t sem, uint32_t time_ms)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

void ls_osa_sem_post(ls_osa_sem_t sem)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

ls_osa_thread_t ls_osa_thread_create(const char *name,
                      void(*func)(void *), void *arg, size_t stack_size)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return NULL;
}

void ls_osa_thread_destroy(ls_osa_thread_t thread)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

#endif /* __DEMO__ */



