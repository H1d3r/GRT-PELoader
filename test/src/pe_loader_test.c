#include <stdio.h>
#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "epilogue.h"
#include "test.h"

__declspec(thread) int tls_var = 0x1234;

static void* copyShellcode();

bool TestInitPELoader()
{
    // append TLS block for this test program
    tls_var++;
    if (tls_var != 0x1235)
    {
        printf("incorrect tls variable value: %d\n", tls_var);
        return false;
    }

    Runtime_Opts opts = {
        .BootInstAddress     = NULL,
        .DisableSysmon       = false,
        .DisableWatchdog     = false,
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }

    // set HashAPI source
    FindAPI_t findAPI;
#ifdef NO_RUNTIME
    findAPI = &FindAPI;
#else
    findAPI = runtime->HashAPI.FindAPI;
#endif // NO_RUNTIME

    // read PE image file
    LPSTR file;
#ifdef _WIN64
    // file = "image\\x64\\go.exe";
    file = "image\\x64\\rust_msvc.exe";
    // file = "image\\x64\\rust_gnu.exe";
    // file = "image\\x64\\ucrtbase_main.exe";
    // file = "image\\x64\\ucrtbase_wmain.exe";
#elif _WIN32
    file = "image\\x86\\go.exe";
    // file = "image\\x86\\rust_msvc.exe";
    // file = "image\\x86\\rust_gnu.exe";
    // file = "image\\x86\\ucrtbase_main.exe";
    // file = "image\\x86\\ucrtbase_wmain.exe";
#endif
    // file = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe";
    // file = "C:\\Windows\\System32\\cmd.exe";
    // file = "C:\\Windows\\System32\\calc.exe";
    // file = "C:\\Windows\\System32\\mscoree.dll";
    // file = "C:\\Windows\\System32\\ole32.dll";
    // file = "C:\\Windows\\System32\\oleaut32.dll";
    // file = "C:\\Windows\\System32\\combase.dll";
    // file = "C:\\Windows\\System32\\ws2_32.dll";

    databuf image;
    errno err = runtime->WinFile.ReadFileA(file, &image);
    if (err != NO_ERROR)
    {
        printf_s("failed to open test pe file: 0x%X\n", err);
        return false;
    }

    LPSTR  cmdLineA = NULL;
    LPWSTR cmdLineW = NULL;

    // cmdLineA =  "loader.exe -kick 10";
    // cmdLineW = L"loader.exe -kick 10";
    // cmdLineA =  "loader.exe -p1 123 -p2 \"test\"";
    // cmdLineW = L"loader.exe -p1 123 -p2 \"test\"";

    PELoader_Cfg cfg = {
        .FindAPI        = findAPI,
        .Image          = image.buf,
        .CommandLineA   = cmdLineA,
        .CommandLineW   = cmdLineW,
        .WaitMain       = true,
        .AllowSkipDLL   = true,
        .IgnoreStdIO    = false,
        .StdInput       = NULL,
        .StdOutput      = NULL,
        .StdError       = NULL,
        .NotStopRuntime = false,

        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
    };
#ifdef SHELLCODE_MODE
    typedef PELoader_M* (*InitPELoader_t)(Runtime_M* runtime, PELoader_Cfg* cfg);
    InitPELoader_t initPELoader = copyShellcode();
    pe_loader = initPELoader(runtime, &cfg);
#else
    pe_loader = InitPELoader(runtime, &cfg);
#endif // SHELLCODE_MODE
    if (pe_loader == NULL)
    {
        printf_s("failed to initialize PE loader: 0x%X\n", GetLastErrno());
        return false;
    }
    // erase PE image after initialize
    RandBuffer(image.buf, image.len);
    return true;
}

static void* copyShellcode()
{
    VirtualAlloc_t VirtualAlloc = FindAPI_A("kernel32.dll", "VirtualAlloc");

    uintptr begin = (uintptr)(&InitPELoader);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        printf_s("failed to allocate memory: 0x%X\n", GetLastErrno());
        return NULL;
    }
    mem_copy(mem, (void*)begin, size);
    printf_s("shellcode: 0x%zX\n", (uintptr)mem);
    return mem;
}

bool TestPELoader_EXE()
{
    if (pe_loader == NULL)
    {
        return false;
    }
    if (pe_loader->IsDLL)
    {
        return true;
    }

    errno errno = pe_loader->Execute();
    if (errno != NO_ERROR)
    {
        printf_s("failed to execute: 0x%X\n", errno);
        return false;
    }

    runtime->Thread.Sleep(3000);

    errno = pe_loader->Exit(0);
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool TestPELoader_DLL()
{
    if (pe_loader == NULL)
    {
        return false;
    }
    if (!pe_loader->IsDLL)
    {
        return true;
    }

    errno errno = pe_loader->Execute();
    if (errno != NO_ERROR)
    {
        printf_s("failed to execute: 0x%X\n", errno);
        return false;
    }

    // test ws2_32.dll
    // void* connect1 = pe_loader->GetProc("connect");
    // printf_s("address1: 0x%zX\n", (uintptr)connect1);
    // void* connect2 = pe_loader->GetProc((LPSTR)(4));
    // printf_s("address2: 0x%zX\n", (uintptr)connect2);
    // if (connect1 != connect2)
    // {
    //     printf_s("incorrect function address by name and ordinal\n");
    //     return false;
    // }

    runtime->Thread.Sleep(3000);

    errno = pe_loader->Exit(0);
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool TestPELoader_Start()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    if (pe_loader->IsDLL)
    {
        return true;
    }

    errno errno = pe_loader->Start();
    if (errno != NO_ERROR)
    {
        printf_s("failed to start: 0x%X\n", errno);
        return false;
    }

    errno = pe_loader->Wait();
    if (errno != NO_ERROR)
    {
        printf_s("failed to wait: 0x%X\n", errno);
        return false;
    }

    errno = pe_loader->Wait();
    if (errno != ERR_LOADER_PROCESS_IS_NOT_START)
    {
        printf_s("failed to wait twice\n");
        return false;
    }
    return true;
}

bool TestPELoader_Exit()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    if (pe_loader->IsDLL)
    {
        return true;
    }

    errno errno = pe_loader->Start();
    if (errno != NO_ERROR)
    {
        printf_s("failed to start: 0x%X\n", errno);
        return false;
    }

    runtime->Thread.Sleep(1000);

    errno = pe_loader->Exit(123);
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%X\n", errno);
        return false;
    }

    uint code = pe_loader->ExitCode();
    if (code != 123)
    {
        printf_s("unexpected exit code\n");
        return false;
    }
    return true;
}

bool TestPELoader_Destroy()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    errno errno = pe_loader->Execute();
    if (errno != NO_ERROR)
    {
        printf_s("failed to execute: 0x%X\n", errno);
        return false;
    }

    runtime->Thread.Sleep(3000);

    errno = pe_loader->Destroy();
    if (errno != NO_ERROR)
    {
        printf_s("failed to destroy PE loader: 0x%X\n", errno);
        return false;
    }

    // check the TLS status
    tls_var++;
    if (tls_var != 0x1236)
    {
        printf("incorrect tls variable value: %d\n", tls_var);
        return false;
    }
    return true;
}
