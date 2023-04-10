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

#include "co.h"
#include "co_epoll.h"
#include "co_inner.h"
#include "coctx.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <string>
// #include <map>

#include <errno.h>
#include <poll.h>
#include <sys/time.h>

#include <assert.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

co_t *get_current_co_by(co_env_t *env);
struct co_epoll_s;

struct co_env_s {
  co_t *pCallStack[128];
  int iCallStackSize;
  co_epoll_t *pEpoll;

  // for copy stack log lastco and nextco
  co_t *pending_co;
  co_t *occupy_co;
};
// int socket(int domain, int type, int protocol);
void co_log_err(const char *fmt, ...) {}

#if defined(__LIBCO_RDTSCP__)
static unsigned long long counter(void) {
  register uint32_t lo, hi;
  register unsigned long long o;
  __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi)::"%rcx");
  o = hi;
  o <<= 32;
  return (o | lo);
}
static unsigned long long getCpuKhz() {
  FILE *fp = fopen("/proc/cpuinfo", "r");
  if (!fp)
    return 1;
  char buf[4096] = {0};
  fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  char *lp = strstr(buf, "cpu MHz");
  if (!lp)
    return 1;
  lp += strlen("cpu MHz");
  while (*lp == ' ' || *lp == '\t' || *lp == ':') {
    ++lp;
  }

  double mhz = atof(lp);
  unsigned long long u = (unsigned long long)(mhz * 1000);
  return u;
}
#endif

static unsigned long long GetTickMS() {
#if defined(__LIBCO_RDTSCP__)
  static uint32_t khz = getCpuKhz();
  return counter() / khz;
#else
  struct timeval now = {0};
  gettimeofday(&now, NULL);
  unsigned long long u = now.tv_sec;
  u *= 1000;
  u += now.tv_usec / 1000;
  return u;
#endif
}

/* no longer use
static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
                tid = syscall( SYS_gettid );
                if( -1 == (long)tid )
                {
                        tid = pid;
                }
#elif defined( __FreeBSD__ )
                syscall(SYS_thr_self, &tid);
                if( tid < 0 )
                {
                        tid = pid;
                }
#else
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
static pid_t GetPid()
{
        char **p = (char**)pthread_self();
        return p ? *(pid_t*)(p + 18) : getpid();
}
*/
#define REMOVE_FROM_LINK(LINK, ap)                                             \
  do {                                                                         \
    LINK *lst = (ap)->pLink;                                                   \
    if (!lst)                                                                  \
      break;                                                                   \
    assert(lst->head && lst->tail);                                            \
    if ((ap) == lst->head) {                                                   \
      lst->head = (ap)->pNext;                                                 \
      if (lst->head) {                                                         \
        lst->head->pPrev = NULL;                                               \
      }                                                                        \
    } else {                                                                   \
      if ((ap)->pPrev) {                                                       \
        (ap)->pPrev->pNext = (ap)->pNext;                                      \
      }                                                                        \
    }                                                                          \
    if ((ap) == lst->tail) {                                                   \
      lst->tail = (ap)->pPrev;                                                 \
      if (lst->tail) {                                                         \
        lst->tail->pNext = NULL;                                               \
      }                                                                        \
    } else {                                                                   \
      (ap)->pNext->pPrev = (ap)->pPrev;                                        \
    }                                                                          \
    (ap)->pPrev = (ap)->pNext = NULL;                                          \
    (ap)->pLink = NULL;                                                        \
  } while (0)

#define ADD_TAIL(apLink, ap)                                                   \
  do {                                                                         \
    if ((ap)->pLink) {                                                         \
      break;                                                                   \
    }                                                                          \
    if (apLink->tail) {                                                        \
      apLink->tail->pNext = /* (TNode *)*/ (ap);                               \
      (ap)->pNext = NULL;                                                      \
      (ap)->pPrev = apLink->tail;                                              \
      apLink->tail = (ap);                                                     \
    } else {                                                                   \
      apLink->head = apLink->tail = (ap);                                      \
      (ap)->pNext = (ap)->pPrev = NULL;                                        \
    }                                                                          \
    (ap)->pLink = apLink;                                                      \
  } while (0)

#define POP_HEAD(NODE, apLink)                                                 \
  do {                                                                         \
    if (!apLink->head) {                                                       \
      break;                                                                   \
    }                                                                          \
    NODE *lp = apLink->head;                                                   \
    if (apLink->head == apLink->tail) {                                        \
      apLink->head = apLink->tail = NULL;                                      \
    } else {                                                                   \
      apLink->head = apLink->head->pNext;                                      \
    }                                                                          \
    lp->pPrev = lp->pNext = NULL;                                              \
    lp->pLink = NULL;                                                          \
    if (apLink->head) {                                                        \
      apLink->head->pPrev = NULL;                                              \
    }                                                                          \
  } while (0)

#define JOIN(NODE, apLink, apOther)                                            \
  do {                                                                         \
    if (!apOther->head) {                                                      \
      break;                                                                   \
    }                                                                          \
    NODE *lp = apOther->head;                                                  \
    while (lp) {                                                               \
      lp->pLink = apLink;                                                      \
      lp = lp->pNext;                                                          \
    }                                                                          \
    lp = apOther->head;                                                        \
    if (apLink->tail) {                                                        \
      apLink->tail->pNext = (NODE *)lp;                                        \
      lp->pPrev = apLink->tail;                                                \
      apLink->tail = apOther->tail;                                            \
    } else {                                                                   \
      apLink->head = apOther->head;                                            \
      apLink->tail = apOther->tail;                                            \
    }                                                                          \
    apOther->head = apOther->tail = NULL;                                      \
  } while (0)

/////////////////for copy stack //////////////////////////
co_stackmem_t *co_alloc_stackmem(unsigned int stack_size) {
  co_stackmem_t *stack_mem = (co_stackmem_t *)malloc(sizeof(co_stackmem_t));
  stack_mem->occupy_co = NULL;
  stack_mem->stack_size = stack_size;
  stack_mem->stack_buffer = (char *)malloc(stack_size);
  stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
  return stack_mem;
}

co_sharestack_t *co_alloc_sharestack(int count, int stack_size) {
  co_sharestack_t *share_stack =
      (co_sharestack_t *)malloc(sizeof(co_sharestack_t));
  share_stack->alloc_idx = 0;
  share_stack->stack_size = stack_size;

  // alloc stack array
  share_stack->count = count;
  co_stackmem_t **stack_array =
      (co_stackmem_t **)calloc(count, sizeof(co_stackmem_t *));
  for (int i = 0; i < count; i++) {
    stack_array[i] = co_alloc_stackmem(stack_size);
  }
  share_stack->stack_array = stack_array;
  return share_stack;
}

static co_stackmem_t *co_get_stackmem(co_sharestack_t *share_stack) {
  if (!share_stack) {
    return NULL;
  }
  int idx = share_stack->alloc_idx++ % share_stack->count;
  //   ++share_stack->alloc_idx;

  return share_stack->stack_array[idx];
}

// ----------------------------------------------------------------------------
typedef struct timeout_item_link_s timeout_item_link_t;
typedef struct timeout_item_s timeout_item_t;
static const int UTHREAD_EPOLL_SIZE = 1024 * 10;
struct co_epoll_s {
  int iEpollFd;

  timeout_t *pTimeout;

  timeout_item_link_t *pstTimeoutList;

  timeout_item_link_t *pstActiveList;

  co_epoll_res *result;
};
typedef void (*on_prepare_fn)(timeout_item_t *, struct epoll_event *ev,
                              timeout_item_link_t *active);
typedef void (*on_process_fn)(timeout_item_t *);
enum {
  eMaxTimeout = 40 * 1000 // 40s
};
#define TIMEOUT_ITEM_FIELDS                                                    \
  timeout_item_t *pPrev;                                                       \
  timeout_item_t *pNext;                                                       \
  timeout_item_link_t *pLink;                                                  \
  unsigned long long ullExpireTime;                                            \
  on_prepare_fn pfnPrepare;                                                    \
  on_process_fn pfnProcess;                                                    \
  void *pArg; /* routine*/                                                     \
  bool bTimeout

struct timeout_item_s {

  TIMEOUT_ITEM_FIELDS;
};
struct timeout_item_link_s {
  timeout_item_t *head;
  timeout_item_t *tail;
};
struct timeout_s {
  timeout_item_link_t *pItems;
  int iItemSize;

  unsigned long long ullStart;
  long long llStartIdx;
};
timeout_t *alloc_timeout(int iSize) {
  timeout_t *lp = (timeout_t *)calloc(1, sizeof(timeout_t));

  lp->iItemSize = iSize;
  lp->pItems = (timeout_item_link_t *)calloc(1, sizeof(timeout_item_link_t) *
                                                    lp->iItemSize);

  lp->ullStart = GetTickMS();
  lp->llStartIdx = 0;

  return lp;
}
void free_timeout(timeout_t *apTimeout) {
  free(apTimeout->pItems);
  free(apTimeout);
}
int add_timeout(timeout_t *apTimeout, timeout_item_t *apItem, uint64_t allNow) {
  if (apTimeout->ullStart == 0) {
    apTimeout->ullStart = allNow;
    apTimeout->llStartIdx = 0;
  }
  if (allNow < apTimeout->ullStart) {
    co_log_err(
        "CO_ERR: add_timeout line %d allNow %llu apTimeout->ullStart %llu",
        __LINE__, allNow, apTimeout->ullStart);

    return __LINE__;
  }
  if (apItem->ullExpireTime < allNow) {
    co_log_err("CO_ERR: add_timeout line %d apItem->ullExpireTime %llu allNow "
               "%llu apTimeout->ullStart %llu",
               __LINE__, apItem->ullExpireTime, allNow, apTimeout->ullStart);

    return __LINE__;
  }
  unsigned long long diff = apItem->ullExpireTime - apTimeout->ullStart;

  if (diff >= (unsigned long long)apTimeout->iItemSize) {
    diff = apTimeout->iItemSize - 1;
    co_log_err("CO_ERR: add_timeout line %d diff %d", __LINE__, diff);

    // return __LINE__;
  }
  timeout_item_link_t *itemlink =
      apTimeout->pItems + (apTimeout->llStartIdx + diff) % apTimeout->iItemSize;
  ADD_TAIL(itemlink, apItem);

  return 0;
}
inline void take_all_timeout(timeout_t *apTimeout, unsigned long long allNow,
                             timeout_item_link_t *apResult) {
  if (apTimeout->ullStart == 0) {
    apTimeout->ullStart = allNow;
    apTimeout->llStartIdx = 0;
  }

  if (allNow < apTimeout->ullStart) {
    return;
  }
  int cnt = allNow - apTimeout->ullStart + 1;
  if (cnt > apTimeout->iItemSize) {
    cnt = apTimeout->iItemSize;
  }
  if (cnt < 0) {
    return;
  }
  for (int i = 0; i < cnt; i++) {
    int idx = (apTimeout->llStartIdx + i) % apTimeout->iItemSize;
    // Join<timeout_item_t, timeout_item_link_t>
    timeout_item_link_t *item = apTimeout->pItems + idx;
    JOIN(timeout_item_t, apResult, item);
  }
  apTimeout->ullStart = allNow;
  apTimeout->llStartIdx += cnt - 1;
}
static void *_co_routine(co_t *uthread, void *) {
  if (uthread->pfn) {
    uthread->pfn(uthread->arg);
  }
  uthread->cEnd = 1;

  co_env_t *env = uthread->env;

  co_yield_env(env);

  return NULL;
}

co_t *co_create_env(co_env_t *env, const co_attr_t *attr, co_routine_fn pfn,
                    void *arg) {

  co_attr_t at;

  if (attr) {
    memcpy(&at, attr, sizeof(at));

    if (at.stack_size <= 0) {
      at.stack_size = 128 * 1024;
    } else if (at.stack_size > 1024 * 1024 * 8) {
      at.stack_size = 1024 * 1024 * 8;
    }

    if (at.stack_size & 0xFFF) {
      at.stack_size &= ~0xFFF;
      at.stack_size += 0x1000;
    }
  } else {
    at.stack_size = 128 * 1024;
    at.share_stack = NULL;
  }

  co_t *lp = (co_t *)malloc(sizeof(co_t));

  memset(lp, 0, (long)(sizeof(co_t)));

  lp->env = env;
  lp->pfn = pfn;
  lp->arg = arg;

  co_stackmem_t *stack_mem = NULL;
  if (at.share_stack) {
    stack_mem = co_get_stackmem(at.share_stack);
    at.stack_size = at.share_stack->stack_size;
  } else {
    stack_mem = co_alloc_stackmem(at.stack_size);
  }
  lp->stack_mem = stack_mem;

  lp->ctx.ss_sp = stack_mem->stack_buffer;
  lp->ctx.ss_size = at.stack_size;

  lp->cStart = 0;
  lp->cEnd = 0;
  lp->cIsMain = 0;
  lp->cEnableSysHook = 0;
  lp->cIsShareStack = at.share_stack != NULL;

  lp->save_size = 0;
  lp->save_buffer = NULL;

  return lp;
}
int co_attr_init(co_attr_t *attr) {
  attr->stack_size = 128 * 1024;
  attr->share_stack = NULL;
  return 0;
}
int co_create(co_t **ppco, const co_attr_t *attr, co_routine_fn pfn,
              void *arg) {
  if (!co_get_curr_thread_env()) {
    co_init_curr_thread_env();
  }
  co_t *uthread = co_create_env(co_get_curr_thread_env(), attr, pfn, arg);
  *ppco = uthread;
  return 0;
}
void co_free(co_t *uthread) {
  if (!uthread->cIsShareStack) {
    free(uthread->stack_mem->stack_buffer);
    free(uthread->stack_mem);
  }
  // walkerdu fix at 2018-01-20
  //存在内存泄漏
  else {
    if (uthread->save_buffer)
      free(uthread->save_buffer);

    if (uthread->stack_mem->occupy_co == uthread)
      uthread->stack_mem->occupy_co = NULL;
  }

  free(uthread);
}
void co_release(co_t *uthread) { co_free(uthread); }

void co_swap(co_t *curr, co_t *pending_co);

void co_resume(co_t *uthread) {
  co_env_t *env = uthread->env;
  co_t *lpCurrRoutine = env->pCallStack[env->iCallStackSize - 1];
  if (!uthread->cStart) {
    coctx_make(&uthread->ctx, (coctx_pfn_t)_co_routine, uthread, 0);
    uthread->cStart = 1;
  }
  env->pCallStack[env->iCallStackSize++] = uthread;
  co_swap(lpCurrRoutine, uthread);
}

// walkerdu 2018-01-14
// 用于reset超时无法重复使用的协程
void co_reset(co_t *uthread) {
  if (!uthread->cStart || uthread->cIsMain)
    return;

  uthread->cStart = 0;
  uthread->cEnd = 0;

  // 如果当前协程有共享栈被切出的buff，要进行释放
  if (uthread->save_buffer) {
    free(uthread->save_buffer);
    uthread->save_buffer = NULL;
    uthread->save_size = 0;
  }

  // 如果共享栈被当前协程占用，要释放占用标志，否则被切换，会执行save_stack_buffer()
  if (uthread->stack_mem->occupy_co == uthread)
    uthread->stack_mem->occupy_co = NULL;
}

void co_yield_env(co_env_t *env) {

  co_t *last = env->pCallStack[env->iCallStackSize - 2];
  co_t *curr = env->pCallStack[env->iCallStackSize - 1];

  --env->iCallStackSize;

  co_swap(curr, last);
}

void co_yield_ct() { co_yield_env(co_get_curr_thread_env()); }
void co_yield (co_t *uthread) { co_yield_env(uthread->env); }

void save_stack_buffer(co_t *occupy_co) {
  /// copy out
  co_stackmem_t *stack_mem = occupy_co->stack_mem;
  int len = stack_mem->stack_bp - occupy_co->stack_sp;

  if (occupy_co->save_buffer) {
    free(occupy_co->save_buffer), occupy_co->save_buffer = NULL;
  }

  occupy_co->save_buffer = (char *)malloc(len); // malloc buf;
  occupy_co->save_size = len;

  memcpy(occupy_co->save_buffer, occupy_co->stack_sp, len);
}

void co_swap(co_t *curr, co_t *pending_co) {
  co_env_t *env = co_get_curr_thread_env();

  // get curr stack sp
  char c;
  curr->stack_sp = &c;

  if (!pending_co->cIsShareStack) {
    env->pending_co = NULL;
    env->occupy_co = NULL;
  } else {
    env->pending_co = pending_co;
    // get last occupy uthread on the same stack mem
    co_t *occupy_co = pending_co->stack_mem->occupy_co;
    // set pending uthread to occupy thest stack mem;
    pending_co->stack_mem->occupy_co = pending_co;

    env->occupy_co = occupy_co;
    if (occupy_co && occupy_co != pending_co) {
      save_stack_buffer(occupy_co);
    }
  }

  // swap context
  coctx_swap(&(curr->ctx), &(pending_co->ctx));

  // stack buffer may be overwrite, so get again;
  co_env_t *curr_env = co_get_curr_thread_env();
  co_t *update_occupy_co = curr_env->occupy_co;
  co_t *update_pending_co = curr_env->pending_co;

  if (update_occupy_co && update_pending_co &&
      update_occupy_co != update_pending_co) {
    // resume stack buffer
    if (update_pending_co->save_buffer && update_pending_co->save_size > 0) {
      memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer,
             update_pending_co->save_size);
    }
  }
}

// int poll(struct pollfd fds[], nfds_t nfds, int timeout);
//  { fd,events,revents }
typedef struct poll_item_s poll_item_t;
typedef struct poll_t poll_t;
struct poll_t {
  TIMEOUT_ITEM_FIELDS;
  struct pollfd *fds;
  nfds_t nfds; // typedef unsigned long int nfds_t;

  poll_item_t *pPollItems;

  int iAllEventDetach;

  int iEpollFd;

  int iRaiseCnt;
};
struct poll_item_s {
  TIMEOUT_ITEM_FIELDS;
  struct pollfd *pSelf;
  poll_t *pPoll;

  struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
FORCE_INLINE uint32_t pool_event2epoll(short events) {
  uint32_t e = 0;
  if (events & POLLIN)
    e |= EPOLLIN;
  if (events & POLLOUT)
    e |= EPOLLOUT;
  if (events & POLLHUP)
    e |= EPOLLHUP;
  if (events & POLLERR)
    e |= EPOLLERR;
  if (events & POLLRDNORM)
    e |= EPOLLRDNORM;
  if (events & POLLWRNORM)
    e |= EPOLLWRNORM;
  return e;
}
FORCE_INLINE short epoll_event2poll(uint32_t events) {
  short e = 0;
  if (events & EPOLLIN)
    e |= POLLIN;
  if (events & EPOLLOUT)
    e |= POLLOUT;
  if (events & EPOLLHUP)
    e |= POLLHUP;
  if (events & EPOLLERR)
    e |= POLLERR;
  if (events & EPOLLRDNORM)
    e |= POLLRDNORM;
  if (events & EPOLLWRNORM)
    e |= POLLWRNORM;
  return e;
}

static __thread co_env_t *gCoEnvPerThread = NULL;

void co_init_curr_thread_env() {
  gCoEnvPerThread = (co_env_t *)calloc(1, sizeof(co_env_t));
  co_env_t *env = gCoEnvPerThread;

  env->iCallStackSize = 0;
  co_t *self = co_create_env(env, NULL, NULL, NULL);
  self->cIsMain = 1;

  env->pending_co = NULL;
  env->occupy_co = NULL;

  coctx_init(&self->ctx);

  env->pCallStack[env->iCallStackSize++] = self;

  co_epoll_t *ev = alloc_epoll();
  set_epoll(env, ev);
}
co_env_t *co_get_curr_thread_env() { return gCoEnvPerThread; }

void _on_poll_process_event(timeout_item_t *ap) {
  co_t *uthread = (co_t *)ap->pArg;
  co_resume(uthread);
}

void _on_poll_prepare(timeout_item_t *ap, struct epoll_event *e,
                      timeout_item_link_t *active) {
  poll_item_t *lp = (poll_item_t *)ap;
  lp->pSelf->revents = epoll_event2poll(e->events);

  poll_t *pPoll = lp->pPoll;
  pPoll->iRaiseCnt++;

  if (!pPoll->iAllEventDetach) {
    pPoll->iAllEventDetach = 1;

    // RemoveFromLink<timeout_item_t, timeout_item_link_t>
    REMOVE_FROM_LINK(timeout_item_link_t, (timeout_item_t *)pPoll);

    ADD_TAIL(active, (timeout_item_t *)pPoll);
  }
}

void co_eventloop(co_epoll_t *ctx, co_eventloop_fn pfn, void *arg) {
  if (!ctx->result) {
    ctx->result = co_epoll_res_alloc(UTHREAD_EPOLL_SIZE);
  }
  co_epoll_res *result = ctx->result;

  for (;;) {
    int ret = co_epoll_wait(ctx->iEpollFd, result, UTHREAD_EPOLL_SIZE, 1);

    timeout_item_link_t *active = (ctx->pstActiveList);
    timeout_item_link_t *timeout = (ctx->pstTimeoutList);

    memset(timeout, 0, sizeof(timeout_item_link_t));

    for (int i = 0; i < ret; i++) {
      timeout_item_t *item = (timeout_item_t *)result->events[i].data.ptr;
      if (item->pfnPrepare) {
        item->pfnPrepare(item, &result->events[i], active);
      } else {
        ADD_TAIL(active, item);
      }
    }

    unsigned long long now = GetTickMS();
    take_all_timeout(ctx->pTimeout, now, timeout);

    timeout_item_t *lp = timeout->head;
    while (lp) {
      // printf("raise timeout %p\n",lp);
      lp->bTimeout = true;
      lp = lp->pNext;
    }

    // Join<timeout_item_t, timeout_item_link_t>
    JOIN(timeout_item_t, active, timeout);

    lp = active->head;
    while (lp) {

      POP_HEAD(timeout_item_t, active);
      if (lp->bTimeout && now < lp->ullExpireTime) {
        int ret = add_timeout(ctx->pTimeout, lp, now);
        if (!ret) {
          lp->bTimeout = false;
          lp = active->head;
          continue;
        }
      }
      if (lp->pfnProcess) {
        lp->pfnProcess(lp);
      }

      lp = active->head;
    }
    if (pfn) {
      if (-1 == pfn(arg)) {
        break;
      }
    }
  }
}
void OnCoroutineEvent(timeout_item_t *ap) {
  co_t *uthread = (co_t *)ap->pArg;
  co_resume(uthread);
}

co_epoll_t *alloc_epoll() {
  co_epoll_t *ctx = (co_epoll_t *)calloc(1, sizeof(co_epoll_t));

  ctx->iEpollFd = co_epoll_create(UTHREAD_EPOLL_SIZE);
  ctx->pTimeout = alloc_timeout(60 * 1000);

  ctx->pstActiveList =
      (timeout_item_link_t *)calloc(1, sizeof(timeout_item_link_t));
  ctx->pstTimeoutList =
      (timeout_item_link_t *)calloc(1, sizeof(timeout_item_link_t));

  return ctx;
}

void free_epoll(co_epoll_t *ctx) {
  if (ctx) {
    free(ctx->pstActiveList);
    free(ctx->pstTimeoutList);
    free_timeout(ctx->pTimeout);
    co_epoll_res_free(ctx->result);
  }
  free(ctx);
}

co_t *get_current_co_by(co_env_t *env) {
  return env->pCallStack[env->iCallStackSize - 1];
}
co_t *get_current_uthread() {
  co_env_t *env = co_get_curr_thread_env();
  if (!env)
    return 0;
  return get_current_co_by(env);
}

typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
int co_poll_inner(co_epoll_t *ctx, struct pollfd fds[], nfds_t nfds,
                  int timeout, poll_pfn_t pollfunc) {
  if (timeout == 0) {
    return pollfunc(fds, nfds, timeout);
  }
  if (timeout < 0) {
    timeout = INT_MAX;
  }
  int epfd = ctx->iEpollFd;
  co_t *self = co_self();

  // 1.struct change
  poll_t *arg = ((poll_t *)malloc(sizeof(poll_t)));
  memset(arg, 0, sizeof(*arg));

  arg->iEpollFd = epfd;
  arg->fds = (struct pollfd *)calloc(nfds, sizeof(struct pollfd));
  arg->nfds = nfds;

  poll_item_t arr[2];
  if (nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack) {
    arg->pPollItems = arr;
  } else {
    arg->pPollItems = (poll_item_t *)malloc(nfds * sizeof(poll_item_t));
  }
  memset(arg->pPollItems, 0, nfds * sizeof(poll_item_t));

  arg->pfnProcess = _on_poll_process_event;
  arg->pArg = get_current_co_by(co_get_curr_thread_env());

  // 2. add epoll
  for (nfds_t i = 0; i < nfds; i++) {
    arg->pPollItems[i].pSelf = arg->fds + i;
    arg->pPollItems[i].pPoll = arg;

    arg->pPollItems[i].pfnPrepare = _on_poll_prepare;
    struct epoll_event *ev = &arg->pPollItems[i].stEvent;

    if (fds[i].fd > -1) {
      ev->data.ptr = arg->pPollItems + i;
      ev->events = pool_event2epoll(fds[i].events);

      int ret = co_epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i].fd, ev);
      if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL) {
        if (arg->pPollItems != arr) {
          free(arg->pPollItems);
          arg->pPollItems = NULL;
        }
        free(arg->fds);
        free(arg);
        return pollfunc(fds, nfds, timeout);
      }
    }
    // if fail,the timeout would work
  }

  // 3.add timeout

  unsigned long long now = GetTickMS();
  arg->ullExpireTime = now + timeout;
  int ret = add_timeout(ctx->pTimeout, (timeout_item_t *)arg, now);
  int iRaiseCnt = 0;
  if (ret != 0) {
    co_log_err("CO_ERR: add_timeout ret %d now %lld timeout %d "
               "arg->ullExpireTime %lld",
               ret, now, timeout, arg->ullExpireTime);
    errno = EINVAL;
    iRaiseCnt = -1;

  } else {
    co_yield_env(co_get_curr_thread_env());
    iRaiseCnt = arg->iRaiseCnt;
  }

  {
    // clear epoll status and memory
    REMOVE_FROM_LINK(timeout_item_link_t, (timeout_item_t *)arg);
    for (nfds_t i = 0; i < nfds; i++) {
      int fd = fds[i].fd;
      if (fd > -1) {
        co_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &arg->pPollItems[i].stEvent);
      }
      fds[i].revents = arg->fds[i].revents;
    }

    if (arg->pPollItems != arr) {
      free(arg->pPollItems);
      arg->pPollItems = NULL;
    }

    free(arg->fds);
    free(arg);
  }

  return iRaiseCnt;
}

int co_poll(co_epoll_t *ctx, struct pollfd fds[], nfds_t nfds, int timeout_ms) {
  return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

void set_epoll(co_env_t *env, co_epoll_t *ev) { env->pEpoll = ev; }
co_epoll_t *co_get_epoll_ct() {
  if (!co_get_curr_thread_env()) {
    co_init_curr_thread_env();
  }
  return co_get_curr_thread_env()->pEpoll;
}
#define HOOK_PTHREAD_SPEC_SIZE 1024
struct stHookPThreadSpec_t {
  co_t *uthread;
  void *value;
};
void *co_getspecific(pthread_key_t key) {
  co_t *uthread = get_current_uthread();
  if (!uthread || uthread->cIsMain) {
    return pthread_getspecific(key);
  }
  return uthread->aSpec[key].value;
}
int co_setspecific(pthread_key_t key, const void *value) {
  co_t *uthread = get_current_uthread();
  if (!uthread || uthread->cIsMain) {
    return pthread_setspecific(key, value);
  }
  uthread->aSpec[key].value = (void *)value;
  return 0;
}

void co_disable_hook_sys() {
  co_t *uthread = get_current_uthread();
  if (uthread) {
    uthread->cEnableSysHook = 0;
  }
}
bool co_is_enable_sys_hook() {
  co_t *uthread = get_current_uthread();
  return (uthread && uthread->cEnableSysHook);
}

co_t *co_self() { return get_current_uthread(); }

// uthread cond
typedef struct co_cond_s co_cond_t;
typedef struct co_cond_item_s co_cond_item_t;
struct co_cond_item_s {
  co_cond_item_t *pPrev;
  co_cond_item_t *pNext;
  co_cond_t *pLink;

  timeout_item_t timeout;
};
struct co_cond_s {
  co_cond_item_t *head;
  co_cond_item_t *tail;
};
static void OnSignalProcessEvent(timeout_item_t *ap) {
  co_t *uthread = (co_t *)ap->pArg;
  co_resume(uthread);
}

co_cond_item_t *co_cond_pop(co_cond_t *link);
int co_cond_signal(co_cond_t *si) {
  co_cond_item_t *sp = co_cond_pop(si);
  if (!sp) {
    return 0;
  }
  REMOVE_FROM_LINK(timeout_item_link_t, &sp->timeout);
  timeout_item_link_t *link = co_get_curr_thread_env()->pEpoll->pstActiveList;
  ADD_TAIL(link, &sp->timeout);

  return 0;
}
int co_cond_broadcast(co_cond_t *si) {
  for (;;) {
    co_cond_item_t *sp = co_cond_pop(si);
    if (!sp)
      return 0;

    REMOVE_FROM_LINK(timeout_item_link_t, &sp->timeout);
    timeout_item_link_t *link = co_get_curr_thread_env()->pEpoll->pstActiveList;
    ADD_TAIL(link, &sp->timeout);
  }

  return 0;
}

int co_cond_timedwait(co_cond_t *link, int ms) {
  co_cond_item_t *psi = (co_cond_item_t *)calloc(1, sizeof(co_cond_item_t));
  psi->timeout.pArg = get_current_uthread();
  psi->timeout.pfnProcess = OnSignalProcessEvent;

  if (ms > 0) {
    unsigned long long now = GetTickMS();
    psi->timeout.ullExpireTime = now + ms;

    int ret = add_timeout(co_get_curr_thread_env()->pEpoll->pTimeout,
                          &psi->timeout, now);
    if (ret != 0) {
      free(psi);
      return ret;
    }
  }
  ADD_TAIL(link, psi);

  co_yield_ct();

  REMOVE_FROM_LINK(co_cond_t, psi);
  free(psi);

  return 0;
}
co_cond_t *co_cond_alloc() { return (co_cond_t *)calloc(1, sizeof(co_cond_t)); }
int co_cond_free(co_cond_t *cc) {
  free(cc);
  return 0;
}

co_cond_item_t *co_cond_pop(co_cond_t *link) {
  co_cond_item_t *p = link->head;
  if (p) {
    POP_HEAD(co_cond_item_t, link);
  }
  return p;
}
