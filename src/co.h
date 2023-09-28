/*
* Tencent is pleased to support the open source community by making Libco
available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __CO_ROUTINE_H__
#define __CO_ROUTINE_H__

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/poll.h>
#ifdef __cplusplus
extern "C" {
#endif
// 1.struct

#define GCC_VERSION                                                            \
  (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

#ifndef ARRAY_LEN
#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifdef __cplusplus
#ifndef CO_CPP
#define CO_CPP(x) x
#endif
#else
#ifndef CO_CPP
#define CO_CPP(...)
#endif
#endif

typedef struct co_s co_t;
typedef struct co_sharestack_s co_sharestack_t;
typedef struct co_attr_s co_attr_t;
struct co_attr_s {
  int stack_size;
  co_sharestack_t *share_stack;
} __attribute__((packed));

// default stack_size = 128 * 1024
int co_attr_init(co_attr_t *);

typedef struct co_epoll_s co_epoll_t;
typedef int (*co_eventloop_fn)(void *);
typedef void *(*co_routine_fn)(void *);

// 2.co_routine

int co_create(co_t **co, const co_attr_t *attr, void *(*routine)(void *),
              void *arg);

void co_resume(co_t *co);
void co_yield (co_t *co);
// FORCE_INLINE void co_yield_ct() { // ct = current thread
//   co_yield_env(co_get_curr_thread_env());
// }
void co_yield_ct(); // ct = current thread
void co_release(co_t *co);
void co_reset(co_t *co);
int co_sleep(int ms, int fd CO_CPP(= -1), int events CO_CPP(= 0));
// FORCE_INLINE int co_sleep(int ms, int fd CO_CPP(= -1), int events CO_CPP(=
// 0)) {
//   struct pollfd pf = {fd, events | POLLERR | POLLHUP, 0};
//   return poll(&pf, 1, ms);
// }
co_t *co_self();

int co_poll(co_epoll_t *ctx, struct pollfd fds[], nfds_t nfds, int timeout_ms);

void co_eventloop(co_epoll_t *ctx, co_eventloop_fn pfn CO_CPP(= NULL),
                  void *arg CO_CPP(= NULL));

// 3.specific

int co_setspecific(pthread_key_t key, const void *value);
void *co_getspecific(pthread_key_t key);

// 4.event

co_epoll_t *co_get_epoll_ct(); // ct = current thread

FORCE_INLINE int co_poll_ct(struct pollfd fds[], nfds_t nfds, int timeout_ms) {
  return co_poll(co_get_epoll_ct(), fds, nfds, timeout_ms);
}
FORCE_INLINE void co_eventloop_ct(co_eventloop_fn pfn CO_CPP(= NULL),
                                  void *arg CO_CPP(= NULL)) {
  return co_eventloop(co_get_epoll_ct(), pfn, arg);
}
// 5.hook syscall ( poll/read/write/recv/send/recvfrom/sendto )

void co_enable_hook_sys();
void co_disable_hook_sys();
bool co_is_enable_sys_hook();

// 6.sync
typedef struct co_cond_s co_cond_t;

co_cond_t *co_cond_alloc();
int co_cond_free(co_cond_t *cc);

int co_cond_signal(co_cond_t *);
int co_cond_broadcast(co_cond_t *);
int co_cond_timedwait(co_cond_t *, int timeout_ms);

// 7.share stack
co_sharestack_t *co_alloc_sharestack(int iCount, int iStackSize);

// 8.init envlist for hook get/set env
void co_set_env_list(const char *name[], size_t cnt);

void co_log_err(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
