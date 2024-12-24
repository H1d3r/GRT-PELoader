#ifndef DLL_SHELL32_H
#define DLL_SHELL32_H

#include "c_types.h"
#include "win_types.h"

typedef LPWSTR* (*CommandLineToArgvW_t)
(
    LPCWSTR lpCmdLine, int* pNumArgs
);

#endif // DLL_SHELL32_H
