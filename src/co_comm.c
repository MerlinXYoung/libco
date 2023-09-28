#include "co_comm.h"

// clsCoMutex::clsCoMutex() {
//   m_ptCondSignal = co_cond_alloc();
//   m_iWaitItemCnt = 0;
// }

// clsCoMutex::~clsCoMutex() { co_cond_free(m_ptCondSignal); }

// void clsCoMutex::CoLock() {
//   if (m_iWaitItemCnt > 0) {
//     m_iWaitItemCnt++;
//     co_cond_timedwait(m_ptCondSignal, -1);
//   } else {
//     m_iWaitItemCnt++;
//   }
// }

// void clsCoMutex::CoUnLock() {
//   m_iWaitItemCnt--;
//   co_cond_signal(m_ptCondSignal);
// }

int co_mutex_init(co_mutex_t *m) {
  m->m_ptCondSignal = co_cond_alloc();
  m->m_iWaitItemCnt = 0;
  return 0;
}
int co_mutex_destroy(co_mutex_t *m) {
  co_cond_free(m->m_ptCondSignal);
  return 0;
}
int co_mutex_lock(co_mutex_t *m) {
  if (m->m_iWaitItemCnt > 0) {
    m->m_iWaitItemCnt++;
    co_cond_timedwait(m->m_ptCondSignal, -1);
  } else {
    m->m_iWaitItemCnt++;
  }
  return 0;
}
int co_mutex_unlock(co_mutex_t *m) {
  m->m_iWaitItemCnt--;
  co_cond_signal(m->m_ptCondSignal);
  return 0;
}
