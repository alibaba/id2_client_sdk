/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#ifndef _LS_OSA_LIST_H_
#define _LS_OSA_LIST_H_

#include "ls_osa.h"

typedef unsigned long ulong_t;

typedef struct _ls_osa_list_t {
    struct _ls_osa_list_t *next;
    struct _ls_osa_list_t *prev;
} ls_osa_list_t;

static inline void ls_osa_list_init(ls_osa_list_t *head)
{
    head->prev = head;
    head->next = head;
}

static inline void ls_osa_list_add(ls_osa_list_t *head, ls_osa_list_t *node)
{
    node->next = head->next;
    head->next->prev = node;
    head->next = node;
    node->prev = head;
}

static inline void ls_osa_list_add_tail(ls_osa_list_t *head, ls_osa_list_t *node)
{
    node->prev = head->prev;
    head->prev->next = node;
    head->prev = node;
    node->next = head;
}

static inline void ls_osa_list_del(ls_osa_list_t *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node->next = 0;
}

#define ls_osa_list_empty(list) ((list)->next == list)

#define ls_osa_list_entry(addr, type, member) ({             \
    type tmp;                                                \
    ulong_t offset = (ulong_t)(&tmp.member) - (ulong_t)&tmp; \
    (type *)((ulong_t)addr - offset);                        \
})

#define ls_osa_list_iterate(head, entry)                     \
    for ((entry) = (head)->next; (entry) != (head); (entry) = (entry)->next)

#define ls_osa_list_iterate_safe(head, entry, n)                  \
    for (entry = (head)->next, n = entry->next; entry != (head);  \
         entry = n, n = entry->next)

#endif /* _LS_OSA_LIST_H_ */
