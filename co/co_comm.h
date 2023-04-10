#pragma once

#include "co.h"
#include <pthread.h>

// class clsCoMutex {
//  public:
//   clsCoMutex();
//   ~clsCoMutex();

//   void CoLock();
//   void CoUnLock();

//  private:
//   co_cond_t* m_ptCondSignal;
//   int m_iWaitItemCnt;
// };

// class clsSmartLock {
//  public:
//   clsSmartLock(clsCoMutex* m) {
//     m_ptMutex = m;
//     m_ptMutex->CoLock();
//   }
//   ~clsSmartLock() { m_ptMutex->CoUnLock(); }

//  private:
//   clsCoMutex* m_ptMutex;
// };
#ifdef __cplusplus
extern "C" {
#endif
typedef struct co_mutex_s co_mutex_t;
struct co_mutex_s {
  co_cond_t *m_ptCondSignal;
  int m_iWaitItemCnt;
};

int co_mutex_init(co_mutex_t *);
int co_mutex_destroy(co_mutex_t *);

int co_mutex_lock(co_mutex_t *);
int co_mutex_unlock(co_mutex_t *);

#ifdef __cplusplus
}
#endif