#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef RELEASE_MODE
    #define NAME_LDR_MUTEX_GLOBAL NULL
    #define NAME_LDR_MUTEX_STATUS NULL
#else
#ifdef _WIN64
    #define NAME_LDR_MUTEX_GLOBAL "LDR_Global_x64"
    #define NAME_LDR_MUTEX_STATUS "LDR_Status_x64"
#elif _WIN32
    #define NAME_LDR_MUTEX_GLOBAL "LDR_Global_x86"
    #define NAME_LDR_MUTEX_STATUS "LDR_Status_x86"
#endif
#endif // RELEASE_MODE

#ifndef RELEASE_MODE

bool InitDebugger();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugger() (true)

#define dbg_log(mod, fmt, ...)

#endif // RELEASE_MODE

#endif // DEBUG_H
