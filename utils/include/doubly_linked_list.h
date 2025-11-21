/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_IPC_DOUBLY_LINKED_LIST_H
#define OHOS_IPC_DOUBLY_LINKED_LIST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct DL_LIST {
    struct DL_LIST *pstPrev; /* < Current node's pointer to the previous node */
    struct DL_LIST *pstNext; /* < Current node's pointer to the next node */
} DL_LIST;

/* List initialize */
static inline void DLListInit(DL_LIST *list)
{
    list->pstNext = list;
    list->pstPrev = list;
}

/* Get list head node */
#define DL_GET_LIST_HEAD(object) ((object)->pstNext)

/* Get list tail node */
#define DL_GET_LIST_TAIL(object) ((object)->pstPrev)

/* Insert a new node to list. */
static inline void DLListAdd(DL_LIST *list, DL_LIST *node)
{
    node->pstNext = list->pstNext;
    node->pstPrev = list;
    list->pstNext->pstPrev = node;
    list->pstNext = node;
}

/* Insert a node to the tail of a list. */
static inline void DLListTailInsert(DL_LIST *list, DL_LIST *node)
{
    DLListAdd(list->pstPrev, node);
}

/* Insert a new node to list. */
static inline void DLListInsert(DL_LIST *list, DL_LIST *node)
{
    DLListAdd(list, node);
}

/* Delete a specified node from list. */
static inline void DLListDelete(DL_LIST *node)
{
    node->pstNext->pstPrev = node->pstPrev;
    node->pstPrev->pstNext = node->pstNext;
    node->pstNext = NULL;
    node->pstPrev = NULL;
}

/* Check list is empty. */
static inline bool DLListEmpty(DL_LIST *list)
{
    return (bool)(list->pstNext == list);
}

/* Obtain the pointer to a list in a structure. */
#define DL_OFF_SET_OF(type, member) ((size_t)&((type *)0)->member)

/* Obtain the pointer to a structure that contains a list. */
#define DL_LIST_ENTRY(item, type, member) \
    ((type *)(void *)((char *)(item) - DL_OFF_SET_OF(type, member)))

/* Iterate over a list of given type. */
#define DL_LIST_FOR_EACH_ENTRY(item, list, type, member) \
    for ((item) = DL_LIST_ENTRY((list)->pstNext, type, member); \
        ((item) != NULL) && (&(item)->member != (list)); \
        (item) = DL_LIST_ENTRY((item)->member.pstNext, type, member))

/* Iterate over a list safe against removal of list entry. */
#define DL_LIST_FOR_EACH_ENTRY_SAFE(item, next, list, type, member) \
    for ((item) = DL_LIST_ENTRY((list)->pstNext, type, member), \
        (next) = DL_LIST_ENTRY((item)->member.pstNext, type, member); \
        &(item)->member != (list); \
        (item) = (next), (next) = DL_LIST_ENTRY((item)->member.pstNext, type, member))


static inline void DLListDel(DL_LIST *prevNode, DL_LIST *nextNode)
{
    nextNode->pstPrev = prevNode;
    prevNode->pstNext = nextNode;
}

/* Delete node and initialize list */
static inline void ListDeInit(DL_LIST *list)
{
    DLListDel(list->pstPrev, list->pstNext);
    DLListInit(list);
}

/* Iterate over a list. */
#define DL_LIST_FOR_EACH(item, list) \
    for ((item) = (list)->pstNext; \
        (item) != (list); \
        (item) = (item)->pstNext)

/* Iterate over a list safe against removal of list entry. */
#define DL_LIST_FOR_EACH_SAFE(item, next, list) \
    for ((item) = (list)->pstNext, (next) = (item)->pstNext; \
         (item) != (list); \
         (item) = (next), (next) = (item)->pstNext)

/* Initialize a list. */
#define DL_LIST_HEAD(list) DL_LIST list = { &(list), &(list) }

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* OHOS_IPC_DOUBLY_LINKED_LIST_H */