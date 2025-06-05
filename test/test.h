#ifndef TEST_H
#define TEST_H

#include "c_types.h"
#include "runtime.h"
#include "pe_loader.h"

// define global variables for tests
Runtime_M*  runtime;
PELoader_M* pe_loader;

// define unit tests
#pragma warning(push)
#pragma warning(disable: 4276)
bool TestInitPELoader();
bool TestPELoader_EXE();
bool TestPELoader_DLL();
bool TestPELoader_Start();
bool TestPELoader_Exit();
bool TestPELoader_Destroy();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "InitPELoader",     TestInitPELoader     },
    { "PELoader_EXE",     TestPELoader_EXE     },
    { "PELoader_DLL",     TestPELoader_DLL     },
    { "PELoader_Start",   TestPELoader_Start   },
    { "PELoader_Exit",    TestPELoader_Exit    },
    { "PELoader_Destroy", TestPELoader_Destroy },
};

#endif // TEST_H
