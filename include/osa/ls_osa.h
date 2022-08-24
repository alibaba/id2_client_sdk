/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#ifndef _LS_OSA_H_
#define _LS_OSA_H_

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
        !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#define LS_LOG_TAG          "<LS_LOG> "

#define LS_NET_TYPE_TCP     0
#define LS_NET_TYPE_UDP     1

#define LS_TIME_INFINITE    -1

typedef void * ls_osa_sem_t;
typedef void * ls_osa_thread_t;

/**
 * @brief format and print data.
 *
 * @param fmt[in]: formatted string.
 */
void ls_osa_print(const char *fmt, ...);

/**
 * @brief write formatted data to a string.
 *
 * @param str[in]:  string that holds written text.
 * @param size[in]: maximum length of character will be written.
 * @param fmt[in]:  string that contains the text to be written.
 *
 * @return: the written length.
 */
int ls_osa_snprintf(char *str, size_t size, const char *fmt, ...);

/**
 * @brief allocates a block of size bytes of memory.
 *
 * @param size[in]: the block size in bytes.
 *
 * @return a pointer to the allocated memory.
 */
void *ls_osa_malloc(size_t size);

/**
 * @brief allocates memory for an array of nmemb elements of size bytes each,
 *        the memory is set to zero.
 *
 * @param nmemb[in]: array elements item counts.
 * @param size[in]: size in bytes for every array elements.
 *
 * @return a pointer to the allocated memory.
 */
void *ls_osa_calloc(size_t nmemb, size_t size);

/**
 * @brief frees the memory space pointed to by ptr.
 */
void ls_osa_free(void *ptr);

/**
 * @brief sleep thread itself.
 *
 * @param msec[in]: the time interval to be suspended, in milliseconds.
 */
void ls_osa_msleep(unsigned int msec);

/* @brief get current timestamp in milliseconds.
 *
 * @return: timestamp.
 */
long long ls_osa_get_time_ms(void);

/**
 * @brief create a mutex.
 *
 * @param mutex[out]: pointer to the created mutex.
 *
 * @return 0 if success; < 0 if error.
 */
int ls_osa_mutex_create(void **mutex);

/**
 * @brief destroy the created mutex.
 *
 * @param mutex[in]: pointer to the created mutex.
 */
void ls_osa_mutex_destroy(void *mutex);

/**
 * @brief lock the created mutex.
 *
 * @param mutex[in]: pointer to the created mutex.
 */
int ls_osa_mutex_lock(void *mutex);

/**
 * @brief unlock the created mutex.
 *
 * @param mutex[in]: pointer to the created mutex.
 */
int ls_osa_mutex_unlock(void *mutex);

/**
 * @brief initiate a connection with host:port in the given net type.
 *
 * @param host[in]: host to connect to.
 * @param port[in]: port to connect to.
 * @param type[in]: LS_NET_TYPE_xxx.
 *
 * @return: the created network handle, or -1 if error.
 */
int ls_osa_net_connect(const char *host, const char *port, int type);

/**
 * @brief shutdown the connection and free associated data.
 *
 * @param fd[in]: specify the created connection.
 */
void ls_osa_net_disconnect(int fd);

/**
 * @brief send at most 'len' characters.
 *
 * @param fd[in]: specify the created connection.
 * @param buf[in]: the buffer to read from.
 * @param len[in]: the length of the buffer.
 * @param ret_orig[in]: pointer to a variable which will contain the return origin
 *                      -1: the proccess is interrupted, need to retry again.
 *
 * @return: the actual amount send, or -1 if error.
 */
int ls_osa_net_send(int fd, unsigned char *buf, size_t len, int *ret_orig);

/**
 * @brief recv at most 'len' characters, blocking for at most 'timeout' miliseconds.
 *
 * @param fd[in]: specify the created connection.
 * @param buf[in]: the buffer to write to.
 * @param len[in]: maximum length of the buffer.
 * @param timeout[in]: maximum number of milliseconds to wait for data
 *                     0 means no timeout (wait forever).
 * @param ret_orig[in]: pointer to a variable which will contain the return origin
 *                      -1: the operation is interrupted, need to retry again.
 *                      -2: the operation timed out.
 *
 * @return: the actual amount recv, or -1 if error.
 */
int ls_osa_net_recv(int fd, unsigned char *buf, size_t len, int timeout, int *ret_orig);

/**
 * @brief create a semaphore.
 *
 * @param init_val[in]: the initial value for the semaphore.
 *
 * @return the created semaphore if success; NULL if error.
 */
ls_osa_sem_t ls_osa_sem_create(uint32_t init_val);

/**
 * @brief destroy the created semaphore.
 *
 * @param sem[in]: pointer to the created semaphore.
 */
void ls_osa_sem_destroy(ls_osa_sem_t sem);

/**
 * @brief decrement the created semaphore.
 *
 * @param sem[in]: poniter to the created semaphore.
 * @param time_ms[in]: the amount of miliseconds that should be blocked if
 *                     the decrement can not be immediately performed.
 *
 * @note time_ms == LS_TIME_INFINITE, block until the decrement can proceed.
 *
 * @return 0 if success; < 0 if error.
 */
int ls_osa_sem_wait(ls_osa_sem_t sem, uint32_t time_ms);

/**
 * @brief increment the created semaphore.
 *
 * @param sem[in]: pointer to the created semaphore.
 */
void ls_osa_sem_post(ls_osa_sem_t sem);

/**
 * @brief create a new thread.
 *
 * @param name[in]: the name of thread.
 * @param func[in]: the thread execution function.
 * @param arg[in]:  the argument of the thread execution function.
 * @param stack_size[in]: the at least stack size of the created thread.
 *
 * @return the created thread handle if success; NULL if error.
 */
ls_osa_thread_t ls_osa_thread_create(const char *name,
                      void(*func)(void *), void *arg, size_t stack_size);

/**
 * @brief terminate the create thread.
 *
 * @param thread[in]: pointer to the created thread.
 */
void ls_osa_thread_destroy(ls_osa_thread_t thread);

#endif /* _LS_OSA_H_ */

