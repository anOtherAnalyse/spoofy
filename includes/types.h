#ifndef _RAW_TYPES_H_
#define _RAW_TYPES_H_

typedef unsigned char uint8_t;
typedef signed char int8_t;

typedef unsigned short int uint16_t;
typedef signed short int int16_t;

typedef unsigned int uint32_t;
typedef signed int int32_t;

#ifdef __MACH__
  typedef unsigned long long uint64_t;
  typedef signed long long int64_t;
#elif __linux__
  typedef unsigned long int uint64_t;
  typedef signed long int int64_t;
#endif

#endif
