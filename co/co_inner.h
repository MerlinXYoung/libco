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

#ifndef __CO_ROUTINE_INNER_H__

#include "co.h"
#include "coctx.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct co_env_s co_env_t;
typedef struct co_spec_s co_spec_t;
struct co_spec_s {
  void *value;
};
typedef struct co_stackmem_s co_stackmem_t;
struct co_stackmem_s {
  co_t *occupy_co;
  int stack_size;
  char *stack_bp; // stack_buffer + stack_size
  char *stack_buffer;
};
typedef struct co_sharestack_s co_sharestack_t;
struct co_sharestack_s {
  unsigned int alloc_idx;
  int stack_size;
  int count;
  co_stackmem_t **stack_array;
};

struct co_s {
  co_env_t *env;
  co_routine_fn pfn;
  void *arg;
  coctx_t ctx;

  char cStart;
  char cEnd;
  char cIsMain;
  char cEnableSysHook;
  char cIsShareStack;

  void *pvEnv;

  // char sRunStack[ 1024 * 128 ];
  co_stackmem_t *stack_mem;

  // save satck buffer while confilct on same stack_buffer;
  char *stack_sp;
  unsigned int save_size;
  char *save_buffer;

  co_spec_t aSpec[1024];
};

// 1.env
void co_init_curr_thread_env();
co_env_t *co_get_curr_thread_env();

// 2.coroutine
void co_free(co_t *uthread);
void co_yield_env(co_env_t *env);

// 3.func

//-----------------------------------------------------------------------------------------------

typedef struct timeout_s timeout_t;
typedef struct timeout_item_s timeout_item_t;

timeout_t *alloc_timeout(int iSize);
void free_timeout(timeout_t *apTimeout);
int add_timeout(timeout_t *apTimeout, timeout_item_t *apItem, uint64_t allNow);

struct co_epoll_s;
co_epoll_t *alloc_epoll();
void free_epoll(co_epoll_t *ctx);

co_t *get_current_uthread();
void set_epoll(co_env_t *env, co_epoll_t *ev);

// typedef void (*co_routine_fn)();
#ifdef __cplusplus
}
#endif
#endif

#define __CO_ROUTINE_INNER_H__
