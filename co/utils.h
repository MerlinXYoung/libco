#pragma once
#include <stdint.h>
#include <stdlib.h>

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
#ifndef UTHREAD_CPP
#define UTHREAD_CPP(x) x
#endif
#else
#ifndef UTHREAD_CPP
#define UTHREAD_CPP(...)
#endif
#endif