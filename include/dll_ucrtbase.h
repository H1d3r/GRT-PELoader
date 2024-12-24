#ifndef DLL_UCRTBASE_H
#define DLL_UCRTBASE_H

#include "c_types.h"
#include "win_types.h"

typedef int* (__cdecl *ucrtbase_p_argc_t)();

typedef byte*** (__cdecl *ucrtbase_p_argv_t)();

typedef uint16*** (__cdecl *ucrtbase_p_wargv_t)();

#endif // DLL_UCRTBASE_H
