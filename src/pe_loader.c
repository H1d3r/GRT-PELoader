#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_shell32.h"
#include "dll_msvcrt.h"
#include "dll_ucrtbase.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "pe_image.h"
#include "win_api.h"
#include "random.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "debug.h"

#define MAIN_MEM_PAGE_SIZE 4096

typedef struct {
    // store config from argument
    Runtime_M*   Runtime;
    PELoader_Cfg Config;

    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    LoadLibraryA_t          LoadLibraryA;
    FreeLibrary_t           FreeLibrary;
    GetProcAddress_t        GetProcAddress;
    CreateThread_t          CreateThread;
    ExitThread_t            ExitThread;
    FlushInstructionCache_t FlushInstructionCache;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    CloseHandle_t           CloseHandle;
    GetCommandLineA_t       GetCommandLineA;
    GetCommandLineW_t       GetCommandLineW;
    LocalFree_t             LocalFree;
    GetStdHandle_t          GetStdHandle;

    // loader context
    void*  MainMemPage; // store all structures
    void*  PEBackup;    // PE image backup
    bool   IsRunning;   // execution flag
    HANDLE hMutex;      // global mutex
    HANDLE StatusMu;    // lock loader status

    // store PE image information
    uintptr PEImage;
    uintptr DataDir;
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;
    uintptr Section;

    // store PE image NT header
    Image_FileHeader     FileHeader;
    Image_OptionalHeader OptHeader;

    // store info need fixed when execute
    uintptr ExportTable;
    uint32  ExportTableSize;
    uintptr ImportTable;
    uint32  ImportTableSize;
    uintptr DelayImportTable;
    uint32  DelayImportTableSize;

    // about characteristics
    bool IsDLL;
    bool IsFixed;

    // store TLS data template
    void* TLSBlock;
    uint  TLSLen;

    // store TLS callback list
    TLSCallback_t* TLSList;

    // about command line arguments
    int     argc;
    LPSTR*  argv_a;
    LPWSTR* argv_w;

    // about msvcrt/ucrtbase on exit
    void** on_exit;
    int32  num_exit;

    // write return value
    uint* ExitCode;
} PELoader;

// PE loader methods
void* LDR_GetProc(LPSTR name);
errno LDR_Execute();
errno LDR_Exit(uint exitCode);
errno LDR_Destroy();

// hard encoded address in getPELoaderPointer for replacement
#ifdef _WIN64
    #define PE_LOADER_POINTER 0x7FABCDEF222222FF
#elif _WIN32
    #define PE_LOADER_POINTER 0x7FAB22FF
#endif
static PELoader* getPELoaderPointer();

static bool ldr_lock();
static bool ldr_unlock();

static void* allocPELoaderMemPage(PELoader_Cfg* config);
static bool  initPELoaderAPI(PELoader* loader);
static bool  adjustPageProtect(PELoader* loader, DWORD* old);
static bool  recoverPageProtect(PELoader* loader, DWORD protect);
static bool  updatePELoaderPointer(PELoader* loader);
static bool  recoverPELoaderPointer(PELoader* loader);
static errno initPELoaderEnvironment(PELoader* loader);
static errno loadPEImage(PELoader* loader);
static bool  parsePEImage(PELoader* loader);
static bool  checkPEImage(PELoader* loader);
static bool  mapSections(PELoader* loader);
static bool  fixRelocTable(PELoader* loader);
static bool  initTLSDirectory(PELoader* loader);
static void  prepareExportTable(PELoader* loader);
static void  prepareImportTable(PELoader* loader);
static void  prepareDelayImportTable(PELoader* loader);
static bool  backupPEImage(PELoader* loader);
static bool  lockMainMemPage(PELoader* loader);
static bool  flushInstructionCache(PELoader* loader);
static void  erasePELoaderMethods(PELoader* loader);
static errno cleanPELoader(PELoader* loader);

static void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
static void* ldr_GetMethods(LPCWSTR module, LPCSTR lpProcName);
static errno ldr_init_mutex();
static bool  ldr_lock_status();
static bool  ldr_unlock_status();
static bool  ldr_copy_image();
static void* ldr_process_export(LPSTR name);
static bool  ldr_process_import();
static bool  ldr_process_delay_import();
static void  ldr_alloc_tls_block();
static void  ldr_free_tls_block();
static void  ldr_tls_callback(DWORD dwReason);
static void  ldr_register_exit(void* func);
static void  ldr_do_exit();
static void  ldr_exit_process(UINT uExitCode);
static void  ldr_epilogue();

static HMODULE ldr_load_module(LPSTR name);

static void pe_entry_point();
static bool pe_dll_main(DWORD dwReason, bool setExitCode);
static void set_exit_code(uint code);
static uint get_exit_code();
static void set_running(bool run);
static bool is_running();
static void clean_run_data();
static void reset_handler();
static uint restart_image();

// hooks about kernel32.dll
LPSTR   hook_GetCommandLineA();
LPWSTR  hook_GetCommandLineW();
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);
HANDLE  hook_GetStdHandle(DWORD nStdHandle);
HANDLE  hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);
HANDLE  stub_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, DWORD cc
);
void stub_ExecuteThread(LPVOID lpParameter);
void hook_ExitThread(DWORD dwExitCode);
void hook_ExitProcess(UINT uExitCode);

// hooks about msvcrt.dll
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
);
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
);
int   __cdecl hook_msvcrt_atexit(void* func);
void* __cdecl hook_msvcrt_onexit(void* func);
void* __cdecl hook_msvcrt_dllonexit(void* func, void* pbegin, void* pend);
void  __cdecl hook_msvcrt_exit(int exitcode);

uint __cdecl hook_msvcrt_beginthread(
    void* proc, uint32 stackSize, void* arg
);
uint __cdecl hook_msvcrt_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
);
void __cdecl hook_msvcrt_endthread();
void __cdecl hook_msvcrt_endthreadex(uint32 code);

// hooks about ucrtbase.dll
int*      __cdecl hook_ucrtbase_p_argc();
byte***   __cdecl hook_ucrtbase_p_argv();
uint16*** __cdecl hook_ucrtbase_p_wargv();

int  __cdecl hook_ucrtbase_atexit(void* func);
int  __cdecl hook_ucrtbase_onexit(void* table, void* func);
void __cdecl hook_ucrtbase_exit(int exitcode);

uint __cdecl hook_ucrtbase_beginthread(
    void* proc, uint32 stackSize, void* arg
);
uint __cdecl hook_ucrtbase_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
);
void __cdecl hook_ucrtbase_endthread();
void __cdecl hook_ucrtbase_endthreadex(uint32 code);

void loadCommandLineToArgv();

PELoader_M* InitPELoader(Runtime_M* runtime, PELoader_Cfg* config)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_LOADER_INIT_DEBUGGER);
        return NULL;
    }
    // alloc memory for store loader structure
    void* memPage = allocPELoaderMemPage(config);
    if (memPage == NULL)
    {
        SetLastErrno(ERR_LOADER_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr loaderAddr = address + 1000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 3000 + RandUintN(address, 128);
    // initialize structure
    PELoader* loader = (PELoader*)loaderAddr;
    mem_init(loader, sizeof(PELoader));
    // store config and context
    loader->Runtime = runtime;
    loader->Config  = *config;
    loader->MainMemPage = memPage;
    // initialize loader
    DWORD oldProtect = 0;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initPELoaderAPI(loader))
        {
            errno = ERR_LOADER_INIT_API;
            break;
        }
        if (!adjustPageProtect(loader, &oldProtect))
        {
            errno = ERR_LOADER_ADJUST_PROTECT;
            break;
        }
        if (!updatePELoaderPointer(loader))
        {
            errno = ERR_LOADER_UPDATE_PTR;
            break;
        }
        errno = initPELoaderEnvironment(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        errno = loadPEImage(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!backupPEImage(loader))
        {
            errno = ERR_LOADER_BACKUP_PE_IMAGE;
            break;
        }
        if (!lockMainMemPage(loader))
        {
            errno = ERR_LOADER_LOCK_MAIN_MEM;
            break;
        }
        break;
    }
    if (errno == NO_ERROR || errno > ERR_LOADER_ADJUST_PROTECT)
    {
        erasePELoaderMethods(loader);
    }
    if (oldProtect != 0)
    {
        if (!recoverPageProtect(loader, oldProtect) && errno == NO_ERROR)
        {
            errno = ERR_LOADER_RECOVER_PROTECT;
        }
    }
    if (errno == NO_ERROR && !flushInstructionCache(loader))
    {
        errno = ERR_LOADER_FLUSH_INST;
    }
    if (errno != NO_ERROR)
    {
        cleanPELoader(loader);
        SetLastErrno(errno);
        return NULL;
    }
    // set watchdog reset handler
    runtime->Watchdog.SetHandler(GetFuncAddr(&reset_handler));
    // create methods for loader
    PELoader_M* module = (PELoader_M*)moduleAddr;
    // process variables
    module->ImageBase  = (void*)(loader->PEImage);
    module->EntryPoint = (void*)(loader->EntryPoint);
    module->IsDLL      = loader->IsDLL;
    module->ExitCode   = 0;
    // loader module methods
    module->GetProc = GetFuncAddr(&LDR_GetProc);
    module->Execute = GetFuncAddr(&LDR_Execute);
    module->Exit    = GetFuncAddr(&LDR_Exit);
    module->Destroy = GetFuncAddr(&LDR_Destroy);
    // record return value pointer
    loader->ExitCode = &module->ExitCode;
    return module;
}

static void* allocPELoaderMemPage(PELoader_Cfg* config)
{
#ifdef _WIN64
    uint hash = 0xEFE2E03329515B77;
    uint key  = 0x81723B49C5827760;
#elif _WIN32
    uint hash = 0xE0C5DD0C;
    uint key  = 0x1057DA5A;
#endif
    VirtualAlloc_t virtualAlloc = config->FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    SIZE_T size = MAIN_MEM_PAGE_SIZE;
    size += (1 + RandUintN(0, 16)) * 4096;
    LPVOID addr = virtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuffer(addr, (int64)size);
    dbg_log("[PE Loader]", "Main Memory Page: 0x%zX", addr);
    return addr;
}

static bool initPELoaderAPI(PELoader* loader)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x21E5E7E61968BBF4, 0x38FC2BB8B9E8F0B1 }, // VirtualAlloc
        { 0x7DDAB5BF4E742736, 0x6E0D1E4F5D19BE67 }, // VirtualFree
        { 0x6CF439115B558DE1, 0x7CAC9554D5A67E28 }, // VirtualProtect
        { 0x90BD05BA72DD948C, 0x253672CEAE439BB6 }, // LoadLibraryA
        { 0x0322C392AB9AE610, 0x2CF3559162E79E91 }, // FreeLibrary
        { 0xF4E6DE881A59F6A0, 0xBC2E958CCBE70AA2 }, // GetProcAddress
        { 0x62E83480AE0AAFC7, 0x86C0AECD3EF92256 }, // CreateThread
        { 0xE0846C4ED5129CD3, 0x8C8C31D65FAFC1C4 }, // ExitThread
        { 0xE8CA42297DA7319C, 0xAC51BC3A630A84FC }, // FlushInstructionCache
        { 0x04A85D44E64689B3, 0xBB2834EF8BE725C9 }, // CreateMutexA
        { 0x5B84A4B6173E4B44, 0x089FC914B21A66DA }, // ReleaseMutex
        { 0x91BB0A2A34E70890, 0xB2307F73C72A83BD }, // WaitForSingleObject
        { 0xB23064DF64282DE1, 0xD62F5C65075FCCE8 }, // CloseHandle
        { 0xEF31896F2FACEC04, 0x0E670990125E8E48 }, // GetCommandLineA
        { 0x701EF754FFADBDC2, 0x6D5BE783B0AF5812 }, // GetCommandLineW
        { 0xFCB18A0B702E8AB9, 0x8E1D5AE1A2FD9196 }, // LocalFree
        { 0x599C793AB3F4599E, 0xBBBA4AE31D6A6D8F }, // GetStdHandle
    };
#elif _WIN32
    {
        { 0x28310500, 0x51C40B22 }, // VirtualAlloc
        { 0xBC28097D, 0x4483038A }, // VirtualFree
        { 0x7B578622, 0x6950410A }, // VirtualProtect
        { 0x3DAF1E96, 0xD7E436F3 }, // LoadLibraryA
        { 0x2BC5BE30, 0xC2B2D69A }, // FreeLibrary
        { 0xE971801A, 0xEC6F6D90 }, // GetProcAddress
        { 0xD1AFE117, 0xDA772D98 }, // CreateThread
        { 0xC4471F00, 0x6B6811C7 }, // ExitThread
        { 0x73AFF9EE, 0x16AA8D66 }, // FlushInstructionCache
        { 0xFF3A4BBB, 0xD2F55A75 }, // CreateMutexA
        { 0x30B41C8C, 0xDD13B99D }, // ReleaseMutex
        { 0x4DF94300, 0x85D5CD6F }, // WaitForSingleObject
        { 0x7DC545BC, 0xCBD67153 }, // CloseHandle
        { 0xA187476E, 0x5AF922F3 }, // GetCommandLineA
        { 0xC15EF07A, 0x47A945CE }, // GetCommandLineW
        { 0x36B1013C, 0x0852225B }, // LocalFree    
        { 0xAE68A468, 0xD611C7F0 }, // GetStdHandle
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = loader->Config.FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }

    loader->VirtualAlloc          = list[0x00].proc;
    loader->VirtualFree           = list[0x01].proc;
    loader->VirtualProtect        = list[0x02].proc;
    loader->LoadLibraryA          = list[0x03].proc;
    loader->FreeLibrary           = list[0x04].proc;
    loader->GetProcAddress        = list[0x05].proc;
    loader->CreateThread          = list[0x06].proc;
    loader->ExitThread            = list[0x07].proc;
    loader->FlushInstructionCache = list[0x08].proc;
    loader->CreateMutexA          = list[0x09].proc;
    loader->ReleaseMutex          = list[0x0A].proc;
    loader->WaitForSingleObject   = list[0x0B].proc;
    loader->CloseHandle           = list[0x0C].proc;
    loader->GetCommandLineA       = list[0x0D].proc;
    loader->GetCommandLineW       = list[0x0E].proc;
    loader->LocalFree             = list[0x0F].proc;
    loader->GetStdHandle          = list[0x10].proc;
    return true;
}

// CANNOT merge updatePELoaderPointer and recoverPELoaderPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updatePELoaderPointer(PELoader* loader)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getPELoaderPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != PE_LOADER_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)loader;
        success = true;
        break;
    }
    return success;
}

static bool recoverPELoaderPointer(PELoader* loader)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getPELoaderPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)loader)
        {
            target++;
            continue;
        }
        *pointer = PE_LOADER_POINTER;
        success = true;
        break;
    }
    return success;
}

static errno initPELoaderEnvironment(PELoader* loader)
{
    // create global mutex
    HANDLE hMutex = loader->CreateMutexA(NULL, false, NAME_LDR_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return ERR_LOADER_CREATE_G_MUTEX;
    }
    loader->hMutex = hMutex;
    // lock mutex
#ifndef NO_RUNTIME
    if (!loader->Runtime->Resource.LockMutex(hMutex))
    {
        loader->CloseHandle(hMutex);
        return ERR_LOADER_LOCK_G_MUTEX;
    }
#endif // NO_RUNTIME
    return NO_ERROR;
}

static errno loadPEImage(PELoader* loader)
{
    if (!parsePEImage(loader))
    {
        return ERR_LOADER_PARSE_PE_IMAGE;
    }
    if (!checkPEImage(loader))
    {
        return ERR_LOADER_CHECK_PE_IMAGE;
    }
    if (!mapSections(loader))
    {
        return ERR_LOADER_MAP_SECTIONS;
    }
    if (!fixRelocTable(loader))
    {
        return ERR_LOADER_FIX_RELOC_TABLE;
    }
    if (!initTLSDirectory(loader))
    {
        return ERR_LOADER_INIT_TLS_DIRECTORY;
    }
    prepareExportTable(loader);
    prepareImportTable(loader);
    prepareDelayImportTable(loader);
    dbg_log("[PE Loader]", "PE Image: 0x%zX", loader->PEImage);
    return NO_ERROR;
}

static bool parsePEImage(PELoader* loader)
{
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    // check image file header
    if (imageAddr == 0)
    {
        return false;
    }
    if ((*(byte*)(imageAddr+0)^0x7C) != ('M'^0x7C))
    {
        return false;
    }
    if ((*(byte*)(imageAddr+1)^0xA3) != ('Z'^0xA3))
    {
        return false;
    }
    // skip DOS stub
    uint32  peOffset = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    uintptr peBase = imageAddr + peOffset + NT_HEADER_SIGNATURE_SIZE;
    // parse FileHeader
    Image_FileHeader* fileHeader = (Image_FileHeader*)(peBase);
    // check is a executable image
    WORD characteristics = fileHeader->Characteristics;
    if (!(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        return false;
    }
    // erase timestamp in file header
    fileHeader->TimeDateStamp = 0;
    // parse OptionalHeader
    uintptr headerAddr = peBase + sizeof(Image_FileHeader);
#ifdef _WIN64
    Image_OptionalHeader* optHeader = (Image_OptionalHeader64*)(headerAddr);
#elif _WIN32
    Image_OptionalHeader* optHeader = (Image_OptionalHeader32*)(headerAddr);
#endif
    // calculate data directory offset
    uint16  ddOffset = arrlen(optHeader->DataDirectory) * sizeof(Image_DataDirectory);
    uintptr dataDir  = headerAddr + sizeof(Image_OptionalHeader) - ddOffset;
    // calculate the address of the first Section
    uintptr section = headerAddr + sizeof(Image_OptionalHeader);
    // store result
    loader->DataDir    = dataDir;
    loader->EntryPoint = optHeader->AddressOfEntryPoint;
    loader->ImageBase  = optHeader->ImageBase;
    loader->ImageSize  = optHeader->SizeOfImage;
    loader->Section    = section;
    loader->FileHeader = *fileHeader;
    loader->OptHeader  = *optHeader;
    loader->IsDLL   = characteristics & IMAGE_FILE_DLL;
    loader->IsFixed = characteristics & IMAGE_FILE_RELOCS_STRIPPED;
    return true;
}

static bool checkPEImage(PELoader* loader)
{
    Image_FileHeader* FileHeader = &loader->FileHeader;
    // check PE image architecture
#ifdef _WIN64
    uint16 arch = IMAGE_FILE_MACHINE_AMD64;
#elif _WIN32
    uint16 arch = IMAGE_FILE_MACHINE_I386;
#endif
    if (arch != FileHeader->Machine)
    {
        return false;
    }
    dbg_log("[PE Loader]", "Characteristics: 0x%X", FileHeader->Characteristics);
    return true;
}

static bool mapSections(PELoader* loader)
{
    // select the memory page address
    LPVOID base = NULL;
    if (loader->IsFixed)
    {
        base = (LPVOID)(loader->OptHeader.ImageBase);
    }
    // append random memory size to image tail
    uint64 seed = (uint64)(GetFuncAddr(&InitPELoader));
    uint32 size = loader->ImageSize;
    size += (uint32)((1 + RandUintN(seed, 128)) * 4096);
    // allocate memory for write PE image
    void* mem = loader->VirtualAlloc(base, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    loader->PEImage = (uintptr)mem;
    // adjust memory page for execute PE image
    DWORD old;
    if (!loader->VirtualProtect(mem, size, PAGE_EXECUTE_READWRITE, &old))
    {
        return false;
    }
    // lock memory region with special argument for reuse PE image
#ifndef NO_RUNTIME
    if (!loader->Runtime->Memory.Lock(mem))
    {
        return false;
    }
#endif // NO_RUNTIME
    // map PE image sections to the memory
    uintptr peImage   = (uintptr)mem;
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    Image_SectionHeader* section = (Image_SectionHeader*)(loader->Section);
    for (uint16 i = 0; i < loader->FileHeader.NumberOfSections; i++)
    {
        uint32 virtualAddress   = section->VirtualAddress;
        uint32 sizeOfRawData    = section->SizeOfRawData;
        uint32 pointerToRawData = section->PointerToRawData;
        byte* dst = (byte*)(peImage + virtualAddress);
        byte* src = (byte*)(imageAddr + pointerToRawData);
        mem_copy(dst, src, sizeOfRawData);
        section++;
    }
    // update EntryPoint absolute address
    loader->EntryPoint += peImage;
    return true;
}

static bool fixRelocTable(PELoader* loader)
{
    if (loader->IsFixed)
    {
        return true;
    }
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);
    uintptr relocTable = peImage + dd.VirtualAddress;
    uint32  tableSize  = dd.Size;
    // check need relocation
    if (tableSize == 0)
    {
        return true;
    }
    void*  tableAddr  = (void*)relocTable; // for erase table after
    uint64 addrOffset = (int64)(loader->PEImage) - (int64)(loader->ImageBase);
    for (;;)
    {
        Image_BaseRelocation* baseReloc = (Image_BaseRelocation*)(relocTable);
        if (baseReloc->VirtualAddress == 0)
        {
            break;
        }
        uintptr relocPtr = relocTable + 8;
        uintptr dstAddr  = peImage + baseReloc->VirtualAddress;
        for (uint32 i = 0; i < (baseReloc->SizeOfBlock - 8) / 2; i++)
        {
            Image_Reloc reloc = *(Image_Reloc*)(relocPtr);
            uint32* patchAddr32;
            uint64* patchAddr64;
            switch (reloc.Type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                patchAddr32 = (uint32*)(dstAddr + reloc.Offset);
                *patchAddr32 += (uint32)(addrOffset);
                break;
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (uint64*)(dstAddr + reloc.Offset);
                *patchAddr64 += (uint64)(addrOffset);
                break;
            default:
                return false;
            }
            relocPtr += sizeof(Image_Reloc);
        }
        relocTable += baseReloc->SizeOfBlock;
    }
    // destroy table for prevent extract raw PE image
    RandBuffer(tableAddr, tableSize);
    return true;
}

static bool initTLSDirectory(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_TLS * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);
    uintptr tlsTable  = peImage + dd.VirtualAddress;
    uint32  tableSize = dd.Size;
    // check need initialize tls callback
    if (tableSize == 0)
    {
        return true;
    }
    Image_TLSDirectory* tls = (Image_TLSDirectory*)(tlsTable);
    // allocate memory for copy tls template data, the first 16 bytes
    // for store original TLS address and make sure 16 bytes-aligned
    uint size  = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
    uint total = 16 + size + tls->SizeOfZeroFill;
    // allocate memory for save tls template data
    uint  pSize = total + (uint)((1 + RandUintN((uint64)tls, 8)) * 4096);
    void* block = loader->VirtualAlloc(NULL, pSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (block == NULL)
    {
        return false;
    }
    RandBuffer(block, (int64)size);
    loader->TLSBlock = block;
    loader->TLSLen   = total;
#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->Runtime->Memory.Lock(block))
    {
        return false;
    }
#endif // NO_RUNTIME
    uintptr start = (uintptr)block + 16;
    mem_copy((void*)(start), (void*)(tls->StartAddressOfRawData), size);
    mem_init((void*)(start + size), tls->SizeOfZeroFill);
    dbg_log("[PE Loader]", "TLS block template: 0x%zX", block);
    // record tls callback list
    loader->TLSList = (TLSCallback_t*)(tls->AddressOfCallBacks);
    // destroy tls template data and tls table for prevent extract raw PE image
    RandBuffer((byte*)(tls->StartAddressOfRawData), size);
    RandBuffer((byte*)tlsTable, tableSize);
    return true;
}

static void prepareExportTable(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_EXPORT * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);

    loader->ExportTable     = peImage + dd.VirtualAddress;
    loader->ExportTableSize = dd.Size;

    // erase timestamp in PE image
    if (loader->ExportTableSize == 0)
    {
        return;
    }
    Image_ExportDirectory* export = (Image_ExportDirectory*)(loader->ExportTable);
    export->TimeDateStamp = 0;
}

static void prepareImportTable(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_IMPORT * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);

    loader->ImportTable     = peImage + dd.VirtualAddress;
    loader->ImportTableSize = dd.Size;

    // erase timestamp in PE image
    if (loader->ImportTableSize == 0)
    {
        return;
    }
    Image_ImportDescriptor* import = (Image_ImportDescriptor*)(loader->ImportTable);
    for (;;)
    {
        if (import->Name == 0)
        {
            break;
        }
        import->TimeDateStamp = 0;
        import++;
    }
}

static void prepareDelayImportTable(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);

    loader->DelayImportTable     = peImage + dd.VirtualAddress;
    loader->DelayImportTableSize = dd.Size;

    // erase timestamp in PE image
    if (loader->DelayImportTableSize == 0)
    {
        return;
    }
    Image_DelayloadDescriptor* dld = (Image_DelayloadDescriptor*)(loader->DelayImportTable);
    for (;;)
    {
        if (dld->DllNameRVA == 0)
        {
            break;
        }
        dld->TimeDateStamp = 0;
        dld++;
    }
}

// backupPEImage is used to execute PE image multi times.
static bool backupPEImage(PELoader* loader)
{
    // append random memory size to tail
    uint64 seed = (uint64)(GetFuncAddr(&InitPELoader)) + 4096;
    uint32 size = loader->ImageSize;
    size += (uint32)((1 + RandUintN(seed, 128)) * 4096);
    // allocate memory for backup PE image
    void* mem = loader->VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    RandBuffer(mem, (int64)size);
    loader->PEBackup = mem;
    // copy mapped PE image
    mem_copy(mem, (void*)(loader->PEImage), loader->ImageSize);
#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->Runtime->Memory.Lock(mem))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

static bool lockMainMemPage(PELoader* loader)
{
#ifndef NO_RUNTIME
    if (!loader->Runtime->Memory.Lock(loader->MainMemPage))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

static bool flushInstructionCache(PELoader* loader)
{
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->FlushInstructionCache(CURRENT_PROCESS, (LPCVOID)begin, size);
}

__declspec(noinline)
static void erasePELoaderMethods(PELoader* loader)
{
    if (loader->Config.NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&allocPELoaderMemPage));
    uintptr end   = (uintptr)(GetFuncAddr(&erasePELoaderMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

// ======================== these instructions will not be erased ========================

// change memory protect for dynamic update pointer that hard encode.
__declspec(noinline)
static bool adjustPageProtect(PELoader* loader, DWORD* old)
{
    if (loader->Config.NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->VirtualProtect((void*)begin, size, PAGE_EXECUTE_READWRITE, old);
}

__declspec(noinline)
static bool recoverPageProtect(PELoader* loader, DWORD protect)
{
    if (loader->Config.NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    DWORD   old;
    return loader->VirtualProtect((void*)begin, size, protect, &old);
}

static errno cleanPELoader(PELoader* loader)
{
    errno errno = NO_ERROR;

    CloseHandle_t closeHandle = loader->CloseHandle;
    VirtualFree_t virtualFree = loader->VirtualFree;

    if (closeHandle != NULL)
    {
        // close global mutex
        if (loader->hMutex != NULL)
        {
            if (!closeHandle(loader->hMutex) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_G_MUTEX;
            }
        }
        // close status mutex
        if (loader->StatusMu != NULL)
        {
            if (!closeHandle(loader->StatusMu) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_S_MUTEX;
            }
        }
    }

    if (virtualFree != NULL)
    {
        void* peImage  = (void*)(loader->PEImage);
        void* peBackup = loader->PEBackup;
        void* tlsBlock = loader->TLSBlock;
        void* memPage  = loader->MainMemPage;

        // release memory page for PE image
        if (peImage != NULL)
        {
            RandBuffer(peImage, loader->ImageSize);
            if (!virtualFree(peImage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_PE_IMAGE;
            }
        }
        // release memory page for PE image backup
        if (peBackup != NULL)
        {
            RandBuffer(peBackup, loader->ImageSize);
            if (!virtualFree(peBackup, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_BACKUP;
            }
        }
        // release memory page for TLS block template
        if (tlsBlock != NULL)
        {
            RandBuffer(tlsBlock, loader->TLSLen);
            if (!virtualFree(tlsBlock, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_TLS_BLOCK;
            }
        }
        // release main memory page
        if (memPage != NULL)
        {
            RandBuffer(memPage, MAIN_MEM_PAGE_SIZE);
            if (!virtualFree(memPage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_MAIN_MEM;
            }
        }
    }
    return errno;
}

// updatePELoaderPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updatePELoaderPointer will fail.
#pragma optimize("", off)
static PELoader* getPELoaderPointer()
{
    uintptr pointer = PE_LOADER_POINTER;
    return (PELoader*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool ldr_lock()
{
    PELoader* loader = getPELoaderPointer();

    DWORD event = loader->WaitForSingleObject(loader->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool ldr_unlock()
{
    PELoader* loader = getPELoaderPointer();

    return loader->ReleaseMutex(loader->hMutex);
}

__declspec(noinline)
void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    PELoader* loader = getPELoaderPointer();

    // process ordinal import
    if (lpProcName < (LPCSTR)(0xFFFF))
    {
        dbg_log("[PE Loader]", "GetProcAddressByOrdinal: %d", lpProcName);
        return loader->GetProcAddress(hModule, lpProcName);
    }
    dbg_log("[PE Loader]", "GetProcAddress: %s", lpProcName);
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    uint16 module[MAX_PATH];
    mem_init(module, sizeof(module));
    // get module file name
    if (hModule == HMODULE_GLEAM_RT)
    {
        uint16 mod[] = {
            L'G', L'l', L'e', L'a', L'm', L'R', L'T', 
            L'.', L'd', L'l', L'l', 0x0000,
        };
        mem_copy(module, mod, sizeof(mod));
    } else {
        if (GetModuleFileName(hModule, module, sizeof(module)) == 0)
        {
            SetLastErrno(ERR_LOADER_NOT_FOUND_MODULE);
            return NULL;
        }
    }
    // check is PE Loader internal methods
    void* method = ldr_GetMethods(module, lpProcName);
    if (method != NULL)
    {
        return method;
    }
    return loader->GetProcAddress(hModule, lpProcName);
}

__declspec(noinline)
static void* ldr_GetMethods(LPCWSTR module, LPCSTR lpProcName)
{
    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0x1DE95D906D270C1E, 0x2672227B97F5DAD9, GetFuncAddr(&ldr_GetProcAddress)          },
        { 0x1848E44B66F18C48, 0x16480B2B71CCBA71, GetFuncAddr(&hook_GetCommandLineA)        },
        { 0x6CDF268D5D259686, 0xB2ECF3E4AAC267BA, GetFuncAddr(&hook_GetCommandLineW)        },
        { 0x091A5CA0D803A190, 0x01DDBC313ED0F7ED, GetFuncAddr(&hook_CommandLineToArgvW)     },
        { 0xD64DA86D6A985B33, 0xE8DAF74FBC29AF11, GetFuncAddr(&hook_GetStdHandle)           },
        { 0x9B91E956B96D6389, 0xEBB723BF1CEE4569, GetFuncAddr(&hook_CreateThread)           },
        { 0x053D2B184D2AD724, 0x5DFCC08DACB101DD, GetFuncAddr(&hook_ExitThread)             },
        { 0x003837989C804A7A, 0x77BACCABEB6CE508, GetFuncAddr(&hook_ExitProcess)            },
        { 0x0109ACED1D5A0663, 0x7417D87CE8EBE1AA, GetFuncAddr(&hook_ExitThread)             }, // RtlExitUserThread
        { 0xF0F5DD7990C5EFCF, 0x5461D0002BE008A4, GetFuncAddr(&hook_ExitProcess)            }, // RtlExitUserProcess
        { 0x8D91B93B7BFC89B4, 0x428A7543FADEEF29, GetFuncAddr(&hook_msvcrt_getmainargs)     },
        { 0xB6627A6DDB0A9B1A, 0x729C834DB43EB70A, GetFuncAddr(&hook_msvcrt_wgetmainargs)    },
        { 0x09D5A9F4AFA840B0, 0xAA4A0E457ACEF3AF, GetFuncAddr(&hook_msvcrt_atexit)          },
        { 0x3C03CF70E803FFC9, 0x7DF0A0B4D6DA6C61, GetFuncAddr(&hook_msvcrt_onexit)          },
        { 0xF69B9609BFC3866B, 0x78F57B29208EC83F, GetFuncAddr(&hook_msvcrt_dllonexit)       },
        { 0x4B7D921A385FB3D2, 0xC579F5ED84E53139, GetFuncAddr(&hook_msvcrt_exit)            },
        { 0xCF5B61D9D1D07170, 0x8E81AD35920956CF, GetFuncAddr(&hook_msvcrt_exit)            }, // _exit
        { 0x9C21EEDD7A2A5DDE, 0x662C082531C1CF07, GetFuncAddr(&hook_msvcrt_exit)            }, // _Exit
        { 0x30E025C660C45C1A, 0xFF6D4FB59EA71340, GetFuncAddr(&hook_msvcrt_exit)            }, // _cexit
        { 0x8B0F23118385BCFE, 0x8DCDC63B3ED804BA, GetFuncAddr(&hook_msvcrt_exit)            }, // _c_exit
        { 0x70596B50D6A5DC99, 0xA207B156D6577956, GetFuncAddr(&hook_msvcrt_exit)            }, // quick_exit
        { 0x8D9113B7D97053BE, 0xC2BF1EFCD107A1AE, GetFuncAddr(&hook_msvcrt_exit)            }, // _amsg_exit
        { 0xBEA31032BE54C256, 0xA70BB0D7ED5706AB, GetFuncAddr(&hook_msvcrt_exit)            }, // _o_exit
        { 0x7C58F853C94D7734, 0x01728DEDCEA9827D, GetFuncAddr(&hook_msvcrt_beginthread)     },
        { 0x5A9C7453C029573A, 0x14970FDAB85504CA, GetFuncAddr(&hook_msvcrt_beginthreadex)   },
        { 0x0BD5D73C8548860C, 0x7718D9A31945FC05, GetFuncAddr(&hook_msvcrt_endthread)       },
        { 0xE25BF7B3E1C51A2A, 0xE96A26D024C2EAD7, GetFuncAddr(&hook_msvcrt_endthreadex)     },
        { 0x677E9E5FFC09596F, 0xF0CDF0DC4A6693B0, GetFuncAddr(&hook_ucrtbase_p_argc)        },
        { 0x348408E3C4C1F84A, 0x00D6384B5E49BE4E, GetFuncAddr(&hook_ucrtbase_p_argv)        },
        { 0xE4963C275A179C3A, 0x56818722C1E69D4F, GetFuncAddr(&hook_ucrtbase_p_wargv)       },
        { 0xAA136812DF9EB160, 0x42548B3C4280B19A, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_atexit
        { 0x4E7A26901BB3EC62, 0x386F945605B7A0AC, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_at_quick_exit
        { 0x02C65C1FF64C3E77, 0x6D3D2282E138D2B7, GetFuncAddr(&hook_ucrtbase_onexit)        }, // _register_onexit_function
        { 0xD806168873719B4E, 0x477C6E75E8D61A35, GetFuncAddr(&hook_ucrtbase_exit)          },
        { 0xE2C10C718CBC4B4A, 0x006ACBD0EBFF8DCE, GetFuncAddr(&hook_ucrtbase_exit)          }, // _exit
        { 0x84A9F41391B0C0E4, 0x41C04E4C5EEED31D, GetFuncAddr(&hook_ucrtbase_exit)          }, // _Exit
        { 0xB3AD674905D869E3, 0x31970EFAD3DA5C17, GetFuncAddr(&hook_ucrtbase_exit)          }, // _cexit
        { 0x2ACDB535FEF2CD76, 0x127E8E9F16D87088, GetFuncAddr(&hook_ucrtbase_exit)          }, // _c_exit
        { 0x8B23415012EA8D5B, 0xBA6276780F17E45E, GetFuncAddr(&hook_ucrtbase_exit)          }, // quick_exit
        { 0x3CC1F09F6B644BFA, 0xA620C2F1A2247C65, GetFuncAddr(&hook_ucrtbase_beginthread)   },
        { 0xB37DC4391224F516, 0x5660750ECAE84417, GetFuncAddr(&hook_ucrtbase_beginthreadex) },
        { 0x7617799FD759FB6A, 0x02FED24E7D32EFD4, GetFuncAddr(&hook_ucrtbase_endthread)     },
        { 0xF3FD3C6261671701, 0x4CFA9DEFBF4A8F72, GetFuncAddr(&hook_ucrtbase_endthreadex)   },
    };
#elif _WIN32
    {
        { 0x336C0B7C, 0xE6FD5E12, GetFuncAddr(&ldr_GetProcAddress)          },
        { 0x027AFDAA, 0x6F1EE876, GetFuncAddr(&hook_GetCommandLineA)        },
        { 0x76C60C20, 0x10FA5D7C, GetFuncAddr(&hook_GetCommandLineW)        },
        { 0xABE5D9A9, 0x32898C57, GetFuncAddr(&hook_CommandLineToArgvW)     },
        { 0x7DF993F6, 0x4AB8D860, GetFuncAddr(&hook_GetStdHandle)           },
        { 0x0465FE82, 0x70880E4A, GetFuncAddr(&hook_CreateThread)           },
        { 0x4F0C77BA, 0x89DD7B71, GetFuncAddr(&hook_ExitThread)             },
        { 0xB439D7F0, 0xF97FF53F, GetFuncAddr(&hook_ExitProcess)            },
        { 0x810BA4AF, 0x32504D91, GetFuncAddr(&hook_ExitThread)             }, // RtlExitUserThread
        { 0x8FC383EA, 0xBE3EBDD0, GetFuncAddr(&hook_ExitProcess)            }, // RtlExitUserProcess
        { 0xEC3DD822, 0x91377248, GetFuncAddr(&hook_msvcrt_getmainargs)     },
        { 0x44C32027, 0x354751F7, GetFuncAddr(&hook_msvcrt_wgetmainargs)    },
        { 0x11488404, 0xCC8231AF, GetFuncAddr(&hook_msvcrt_atexit)          },
        { 0xDC46DA5B, 0x3F49D570, GetFuncAddr(&hook_msvcrt_onexit)          },
        { 0xB5450AD6, 0xD0D3330A, GetFuncAddr(&hook_msvcrt_dllonexit)       },
        { 0xF1E55A4D, 0x9A112CBD, GetFuncAddr(&hook_msvcrt_exit)            },
        { 0x80A779FC, 0xB919AF61, GetFuncAddr(&hook_msvcrt_exit)            }, // _exit
        { 0x359F0EBD, 0xC3EADDB1, GetFuncAddr(&hook_msvcrt_exit)            }, // _Exit
        { 0x11DDB94D, 0xB92975A9, GetFuncAddr(&hook_msvcrt_exit)            }, // _cexit
        { 0x91C44932, 0x8C4B60F8, GetFuncAddr(&hook_msvcrt_exit)            }, // _c_exit
        { 0xC4AD4F7C, 0x3122305E, GetFuncAddr(&hook_msvcrt_exit)            }, // quick_exit
        { 0xF2AE4C38, 0x7484F7A7, GetFuncAddr(&hook_msvcrt_exit)            }, // _amsg_exit
        { 0x302015B0, 0xE53271F9, GetFuncAddr(&hook_msvcrt_exit)            }, // _o_exit
        { 0x15D5ECD4, 0x361E1CB1, GetFuncAddr(&hook_msvcrt_beginthread)     },
        { 0x363F1035, 0xACFEC527, GetFuncAddr(&hook_msvcrt_beginthreadex)   },
        { 0x5CDDA35D, 0x4333D46D, GetFuncAddr(&hook_msvcrt_endthread)       },
        { 0x206C521E, 0x9E022665, GetFuncAddr(&hook_msvcrt_endthreadex)     },
        { 0x9E4AA9D4, 0xA97CC100, GetFuncAddr(&hook_ucrtbase_p_argc)        },
        { 0x4029DD68, 0x4F1713D1, GetFuncAddr(&hook_ucrtbase_p_argv)        },
        { 0x21EF5083, 0xA44FD76E, GetFuncAddr(&hook_ucrtbase_p_wargv)       },
        { 0x968EA376, 0xE0415797, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_atexit
        { 0xB1BF5E08, 0x404C0CF9, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_at_quick_exit
        { 0xD3745DD0, 0x67D5DACC, GetFuncAddr(&hook_ucrtbase_onexit)        }, // _register_onexit_function
        { 0x1207ACD2, 0x8560B050, GetFuncAddr(&hook_ucrtbase_exit)          },
        { 0x092BEA87, 0xE370C726, GetFuncAddr(&hook_ucrtbase_exit)          }, // _exit
        { 0x81BCEF46, 0xD0EAB5F5, GetFuncAddr(&hook_ucrtbase_exit)          }, // _Exit
        { 0x73C7582D, 0x3AFEF1E0, GetFuncAddr(&hook_ucrtbase_exit)          }, // _cexit
        { 0xB40F5BCE, 0x3DA209E2, GetFuncAddr(&hook_ucrtbase_exit)          }, // _c_exit
        { 0xE6A5BAB4, 0xCA976959, GetFuncAddr(&hook_ucrtbase_exit)          }, // quick_exit
        { 0x033589BB, 0x2BE6FFB1, GetFuncAddr(&hook_ucrtbase_beginthread)   },
        { 0xD787345F, 0xC0B107F6, GetFuncAddr(&hook_ucrtbase_beginthreadex) },
        { 0xD98CB670, 0xBF7AD081, GetFuncAddr(&hook_ucrtbase_endthread)     },
        { 0xAB1F1EFB, 0x95F5740B, GetFuncAddr(&hook_ucrtbase_endthreadex)   },
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W((uint16*)module, (byte*)lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return methods[i].method;
    }
    return NULL;
}

static errno ldr_init_mutex()
{
    PELoader* loader = getPELoaderPointer();

    // close old status mutex
    if (loader->StatusMu != NULL)
    {
        loader->CloseHandle(loader->StatusMu);
    }
    // create new status mutex
    HANDLE statusMu = loader->CreateMutexA(NULL, false, NAME_LDR_MUTEX_STATUS);
    if (statusMu == NULL)
    {
        return ERR_LOADER_CREATE_S_MUTEX;
    }
    loader->StatusMu = statusMu;
    // lock mutex
#ifndef NO_RUNTIME
    if (!loader->Runtime->Resource.LockMutex(statusMu))
    {
        loader->CloseHandle(statusMu);
        return ERR_LOADER_LOCK_S_MUTEX;
    }
#endif // NO_RUNTIME
    return NO_ERROR;
}

__declspec(noinline)
static bool ldr_lock_status()
{
    PELoader* loader = getPELoaderPointer();

    DWORD event = loader->WaitForSingleObject(loader->StatusMu, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool ldr_unlock_status()
{
    PELoader* loader = getPELoaderPointer();

    return loader->ReleaseMutex(loader->StatusMu);
}

static bool ldr_copy_image()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return false;
    }

    // recovery PE image from backup for process data like global variable
    mem_copy((void*)loader->PEImage, loader->PEBackup, loader->ImageSize);

    return ldr_unlock_status();
}

__declspec(noinline)
static void* ldr_process_export(LPSTR name)
{
    PELoader* loader = getPELoaderPointer();

    if (name == NULL)
    {
        SetLastErrno(ERR_LOADER_EMPTY_PROC_NAME);
        return NULL;
    }
    uintptr peImage     = loader->PEImage;
    uintptr exportTable = loader->ExportTable;
    uint32  tableSize   = loader->ExportTableSize;
    // check need process export
    if (tableSize == 0)
    {
        SetLastErrno(ERR_LOADER_EMPTY_EXPORT_TABLE);
        return NULL;
    }
    Image_ExportDirectory* export = (Image_ExportDirectory*)(exportTable);
    DWORD* aof = (DWORD*)(peImage + export->AddressOfFunctions);
    DWORD* aon = (DWORD*)(peImage + export->AddressOfNames);
    WORD*  aoo = (WORD* )(peImage + export->AddressOfNameOrdinals);
    DWORD base = export->Base;
    // try to find procedure address
    void* address = NULL;
    if (name <= (LPSTR)(0xFFFF))
    {
        // get procedure address by ordinal
        DWORD ordi = (DWORD)(uintptr)(name);
        if (ordi - base <= export->NumberOfFunctions)
        {
            address = (void*)(peImage + (uintptr)(aof[ordi-base]));
        }
    } else {
        // get procedure address by name
        for (uint32 i = base; i < export->NumberOfNames + base; i++)
        {
            LPSTR fn = (LPSTR)(peImage + (uintptr)(aon[i-base]));
            if (strcmp_a(fn, name) != 0)
            {
                continue;
            }
            address = (void*)(peImage + (uintptr)(aof[aoo[i - base]]));
            break;
        }
    }
    if (address == NULL)
    {
        SetLastErrno(ERR_LOADER_PROC_NOT_EXIST);
        return NULL;
    }
    // check it is a forwarded export function
    DWORD funcRVA = (DWORD)((uintptr)address-peImage);
    DWORD eatRVA  = (DWORD)(loader->ExportTable-peImage);
    DWORD eatSize = (DWORD)(loader->ExportTableSize);
    if (funcRVA < eatRVA || funcRVA >= eatRVA + eatSize)
    {
        return address;
    }
    // search the last "." in function name
    byte* exportName = address;
    byte* src = exportName;
    uint  dot = 0;
    for (uint j = 0;; j++)
    {
        byte b = *src;
        if (b == '.')
        {
            dot = j;
        }
        if (b == 0x00)
        {
            break;
        }
        src++;
    }
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte dllName[512];
    mem_init(dllName, sizeof(dllName));
    // prevent array bound when call mem_copy
    if (dot > 500)
    {
        dot = 500;
    }
    mem_copy(dllName, exportName, dot + 1);
    // build DLL name
    dllName[dot+1] = 'd';
    dllName[dot+2] = 'l';
    dllName[dot+3] = 'l';
    dllName[dot+4] = 0x00;
    // load dll if it not loaded
    HMODULE hModule = ldr_load_module(dllName);
    if (hModule == NULL)
    {
        hModule = loader->LoadLibraryA(dllName);
        dbg_log("[PE Loader]", "LoadLibrary: %s for forwarded function", dllName);
    } else {
        dbg_log("[PE Loader]", "Already LoadLibrary: %s forwarded function", dllName);
    }
    if (hModule == NULL)
    {
        SetLastErrno(ERR_LOADER_FORWARDED_MODULE);
        return NULL;
    }
    LPCSTR procName = (LPCSTR)((uintptr)exportName + dot + 1);
    return ldr_GetProcAddress(hModule, procName);
}

__declspec(noinline)
static bool ldr_process_import()
{
    PELoader* loader = getPELoaderPointer();

    uintptr peImage     = loader->PEImage;
    uintptr importTable = loader->ImportTable;
    uint32  tableSize   = loader->ImportTableSize;
    // check need process import
    if (tableSize == 0)
    {
        return true;
    }
    // load library and fix function address
    Image_ImportDescriptor* import = (Image_ImportDescriptor*)(importTable);
    for (;;)
    {
        if (import->Name == 0)
        {
            break;
        }
        LPCSTR  dllName = (LPCSTR)(peImage + import->Name);
        HMODULE hModule = loader->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            if (!loader->Config.AllowSkipDLL)
            {
                return false;
            }
            dbg_log("[PE Loader]", "Skipped Library: %s", dllName);
            import++;
            continue;            
        }
        dbg_log("[PE Loader]", "LoadLibrary: %s", dllName);
        uintptr srcThunk;
        uintptr dstThunk;
        if (import->OriginalFirstThunk != 0)
        {
            srcThunk = peImage + import->OriginalFirstThunk;
        } else {
            srcThunk = peImage + import->FirstThunk;
        }
        dstThunk = peImage + import->FirstThunk;
        // fix function address
        for (;;)
        {
            uintptr value = *(uintptr*)srcThunk;
            if (value == 0)
            {
                break;
            }
            LPCSTR procName;
            if (IMAGE_SNAP_BY_ORDINAL(value))
            {
                procName = (LPCSTR)(value & 0xFFFF);
            } else {
                procName = (LPCSTR)(peImage + value + 2);
            }
            void* proc = ldr_GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            *(uintptr*)dstThunk = (uintptr)proc;
            srcThunk += sizeof(uintptr);
            dstThunk += sizeof(uintptr);
        }
        import++;
    }
    return true;
}

__declspec(noinline)
static bool ldr_process_delay_import()
{
    PELoader* loader = getPELoaderPointer();

    uintptr peImage   = loader->PEImage;
    uintptr dlTable   = loader->DelayImportTable;
    uint32  tableSize = loader->DelayImportTableSize;
    // check need process delay import
    if (tableSize == 0)
    {
        return true;
    }
    Image_DelayloadDescriptor* dld = (Image_DelayloadDescriptor*)(dlTable);
    for (;;)
    {
        if (dld->DllNameRVA == 0)
        {
            break;
        }
        // check the target DLL is loaded
        LPSTR   dllName = (LPSTR)(peImage + dld->DllNameRVA);
        HMODULE hModule = ldr_load_module(dllName);
        if (hModule == NULL)
        {
            hModule = loader->LoadLibraryA(dllName);
            dbg_log("[PE Loader]", "Lazy LoadLibrary: %s", dllName);
        } else {
            dbg_log("[PE Loader]", "Already LoadLibrary: %s", dllName);
        }
        if (hModule == NULL)
        {
            if (!loader->Config.AllowSkipDLL)
            {
                return false;
            }
            dbg_log("[PE Loader]", "Skipped Delay Library: %s", dllName);
            dld++;
            continue;
        }
        Image_ThunkData* nameTable = (Image_ThunkData*)(peImage + dld->ImportNameTableRVA);
        Image_ThunkData* addrTable = (Image_ThunkData*)(peImage + dld->ImportAddressTableRVA);
        Image_ImportByName* ibn;
        for (;;)
        {
            if (nameTable->u1.AddressOfData == 0)
            {
                break;
            }
            LPCSTR procName;
            if (IMAGE_SNAP_BY_ORDINAL(nameTable->u1.Ordinal))
            {
                procName = (LPCSTR)((nameTable->u1.Ordinal) & 0xFFFF);
            } else {
                ibn = (Image_ImportByName*)(peImage + nameTable->u1.AddressOfData);
                procName = (LPCSTR)(ibn->Name);
            }
            void* proc = ldr_GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            addrTable->u1.Function = (QWORD)proc;
            nameTable++;
            addrTable++;
        }
        dld++;
    }
    return true;
}

__declspec(noinline)
static HMODULE ldr_load_module(LPSTR name)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    LPWSTR nameW = runtime->WinBase.ANSIToUTF16(name);
    if (nameW == NULL)
    {
        return NULL;
    }
    HMODULE hModule = GetModuleHandle(nameW);
    runtime->Memory.Free(nameW);
    return hModule;
}

__declspec(noinline)
static void ldr_alloc_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // prepare TLS block data memory page
    void* tls = runtime->Memory.Alloc(loader->TLSLen);
    if (tls == NULL)
    {
        return;
    }
    mem_copy(tls, loader->TLSBlock, loader->TLSLen);

    // read the original TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // store the original TLS block address
    uintptr block = *tlsPtr;
    mem_copy(tls, &block, sizeof(block));

    // replace the original TLS block address
    *tlsPtr = (uintptr)tls + 16;

    dbg_log("[PE Loader]", "allocate TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_free_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // read the hooked TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // read the original TLS block address
    void* tls = (void*)(*tlsPtr - 16);

    // restore the original TLS block address
    *tlsPtr = *(uintptr*)tls;

    // free TLS block data
    runtime->Memory.Free(tls);

    dbg_log("[PE Loader]", "free TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_tls_callback(DWORD dwReason)
{
    PELoader* loader = getPELoaderPointer();

    if (loader->TLSList == NULL)
    {
        return;
    }

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_DETACH");
        break;
    case DLL_THREAD_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_DETACH");
        break;
    }

    TLSCallback_t* list = loader->TLSList;
    while (*list != NULL)
    {
        TLSCallback_t callback = (TLSCallback_t)(*list);
        callback((HMODULE)(loader->PEImage), dwReason, NULL);
        list++;
        dbg_log("[PE Loader]", "call TLS callback: 0x%zX", callback);
    }
}

__declspec(noinline)
static void ldr_register_exit(void* func)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (!ldr_lock_status())
    {
        return;
    }

    // allocate memory for store function pointer
    uint size = sizeof(void*) * (uint)(loader->num_exit + 1);
    loader->on_exit = runtime->Memory.Realloc(loader->on_exit, size);
    // set function pointer
    loader->on_exit[loader->num_exit] = func;
    loader->num_exit++;
    dbg_log("[PE Loader]", "register exit callback: 0x%zX", func);

    ldr_unlock_status();
}

__declspec(noinline)
static void ldr_do_exit()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    int32 num = loader->num_exit;
    for (int32 i = num - 1; i >= 0; i--)
    {
        void (__cdecl *func)() = (void (__cdecl *)())(loader->on_exit[i]);
        func();
        dbg_log("[PE Loader]", "call exit callback: 0x%zX", func);
    }

    ldr_unlock_status();
}

static void ldr_exit_process(UINT uExitCode)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call ldr_exit_process: 0x%zX", uExitCode);

    // make callback about DLL_PROCESS_DETACH
    if (loader->IsDLL)
    {
        pe_dll_main(DLL_PROCESS_DETACH, false);
    }

    if (!runtime->Thread.KillAll())
    {
        dbg_log("[PE Loader]", "failed to kill all threads");
    }

    // execute TLS callback list befor call ExitThread.
    ldr_tls_callback(DLL_PROCESS_DETACH);

    errno err = runtime->Core.Cleanup();
    if (err != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to cleanup: 0x%X", err);
    }

    clean_run_data();
    set_exit_code(uExitCode);
    set_running(false);
}

__declspec(noinline)
LPSTR hook_GetCommandLineA()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineA");

    // try to get it from config
    LPSTR cmdLine = loader->Config.CommandLineA;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineA();
}

__declspec(noinline)
LPWSTR hook_GetCommandLineW()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineW");

    // try to get it from config
    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineW();
}

__declspec(noinline)
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "CommandLineToArgvW: \"%ls\"", lpCmdLine);

    // find shell32.CommandLineToArgvW
#ifdef _WIN64
    uint hash = 0x4A48978496F59E02;
    uint key  = 0xC735570A84698151;
#elif _WIN32
    uint hash = 0xD7007E2E;
    uint key  = 0x15875D48;
#endif
    CommandLineToArgvW_t CommandLineToArgvW = loader->Config.FindAPI(hash, key);
    if (CommandLineToArgvW == NULL)
    {
        return NULL;
    }

    // if lpCmdLine is not L"", call the original function
    uint16 empty[] = { 0x0000 };
    if (strcmp_w((UTF16)lpCmdLine, empty) != 0)
    {
        return CommandLineToArgvW(lpCmdLine, pNumArgs);
    }

    LPWSTR cmdLine = hook_GetCommandLineW();
    return CommandLineToArgvW(cmdLine, pNumArgs);
}

__declspec(noinline)
HANDLE hook_GetStdHandle(DWORD nStdHandle)
{
    PELoader* loader = getPELoaderPointer();

    // try to get it from config
    HANDLE hStdInput  = loader->Config.StdInput;
    HANDLE hStdOutput = loader->Config.StdOutput;
    HANDLE hStdError  = loader->Config.StdError;

    switch (nStdHandle)
    {
    case STD_INPUT_HANDLE:
        if (hStdInput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_INPUT_HANDLE");
            return hStdInput;
        }
        break;
    case STD_OUTPUT_HANDLE:
        if (hStdOutput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_OUTPUT_HANDLE");
            return hStdOutput;
        }
        break;
    case STD_ERROR_HANDLE:
        if (hStdError != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_ERROR_HANDLE");
            return hStdError;
        }
        break;
    }
    return loader->GetStdHandle(nStdHandle);
}

// about calling convention for msvcrt/ucrtbase._beginthread
#define CC_STDCALL 0
#define CC_CDECL   1
#define CC_CLRCALL 2

typedef struct {
    POINTER lpStartAddress;
    LPVOID  lpParameter;
    DWORD   callConvention;
} createThreadCtx;

__declspec(noinline)
HANDLE hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
){
    return stub_CreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId, CC_STDCALL
    );
}

__declspec(noinline)
HANDLE stub_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, DWORD cc
){
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "CreateThread: 0x%zX", lpStartAddress);

    // alloc memory for store actual StartAddress and Parameter
    uint size = sizeof(createThreadCtx);
    size += (1 + RandUintN((uint64)lpParameter, 4)) * 4096;
    LPVOID parameter = runtime->Memory.Alloc(size);
    if (parameter == NULL)
    {
        return NULL;
    }

    createThreadCtx* ctx = (createThreadCtx*)parameter;
    ctx->lpStartAddress = lpStartAddress;
    ctx->lpParameter    = lpParameter;
    ctx->callConvention = cc;

    // create thread at stub, that function will call actual StartAddress
    void* addr = GetFuncAddr(&stub_ExecuteThread);
    HANDLE hThread = loader->CreateThread
    (
        lpThreadAttributes, dwStackSize, addr,
        parameter, dwCreationFlags, lpThreadId
    );
    return hThread;
}

__declspec(noinline)
void stub_ExecuteThread(LPVOID lpParameter)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    // copy arguments from context 
    createThreadCtx* ctx = (createThreadCtx*)lpParameter;
    POINTER startAddress   = ctx->lpStartAddress;
    LPVOID  parameter      = ctx->lpParameter;
    DWORD   callConvention = ctx->callConvention;
    runtime->Memory.Free(lpParameter);

    // execute TLS callback list before call dll_main.
    ldr_alloc_tls_block();
    ldr_tls_callback(DLL_THREAD_ATTACH);

    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_ATTACH, false);
    }

    // execute the function
    switch (callConvention)
    {
    case CC_STDCALL:
      {
        typedef void(__stdcall *func_entry_t)(LPVOID lpParameter);
        func_entry_t entry = (func_entry_t)startAddress;
        entry(parameter);
        break;
      }
    case CC_CDECL:
      {
        typedef void (__cdecl *func_entry_t)(LPVOID lpParameter);
        func_entry_t entry = (func_entry_t)startAddress;
        entry(parameter);
        break;
      }
    case CC_CLRCALL:
      {
        // TODO think it  __clrcall
        typedef void(__stdcall *func_entry_t)(LPVOID lpParameter);
        func_entry_t entry = (func_entry_t)startAddress;
        entry(parameter);
        break;
      }
    default:
        panic(PANIC_UNREACHABLE_CODE);
    }

    hook_ExitThread(0);
}

__declspec(noinline)
void hook_ExitThread(DWORD dwExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "ExitThread: %d", dwExitCode);

    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_DETACH, false);
    }

    // execute TLS callback list after call dll_main.
    ldr_tls_callback(DLL_THREAD_DETACH);
    ldr_free_tls_block();

    loader->ExitThread(dwExitCode);
}

__declspec(noinline)
void hook_ExitProcess(UINT uExitCode)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "ExitProcess: %zu", uExitCode);

    if (!runtime->Thread.KillAll())
    {
        dbg_log("[PE Loader]", "failed to kill all threads");
    }

    // execute TLS callback list befor call ExitThread.
    ldr_tls_callback(DLL_PROCESS_DETACH);
    ldr_free_tls_block();

    errno err = runtime->Core.Cleanup();
    if (err != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to cleanup: 0x%X", err);
    }

    clean_run_data();
    set_exit_code(uExitCode);
    set_running(false);

    loader->ExitThread(0);
}

__declspec(noinline)
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
){
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call msvcrt.__getmainargs");

    // find msvcrt.__getmainargs
#ifdef _WIN64
    uint hash = 0x305F6CF2D8F6B0DE;
    uint key  = 0x4AB3805CF30D6415;
#elif _WIN32
    uint hash = 0xE1E75000;
    uint key  = 0x14BEF388;
#endif
    msvcrt_getmainargs_t getmainargs = loader->Config.FindAPI(hash, key);
    if (getmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = getmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_a;
    }
    return ret;
}

__declspec(noinline)
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
){
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call msvcrt.__wgetmainargs");

    // find msvcrt.__wgetmainargs
#ifdef _WIN64
    uint hash = 0x1C3CFAD70CBF5CC3;
    uint key  = 0x2443BB3D37654188;
#elif _WIN32
    uint hash = 0x44C32027;
    uint key  = 0x354751F7;
#endif
    msvcrt_wgetmainargs_t wgetmainargs = loader->Config.FindAPI(hash, key);
    if (wgetmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = wgetmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_w;
    }
    return ret;
}

__declspec(noinline)
int __cdecl hook_msvcrt_atexit(void* func)
{
    dbg_log("[PE Loader]", "call msvcrt.atexit");
    ldr_register_exit(func);
    return 0;
}

__declspec(noinline)
void* __cdecl hook_msvcrt_onexit(void* func)
{
    dbg_log("[PE Loader]", "call msvcrt._onexit");
    ldr_register_exit(func);
    return func;
}

__declspec(noinline)
void* __cdecl hook_msvcrt_dllonexit(void* func, void* pbegin, void* pend)
{
    dbg_log("[PE Loader]", "call msvcrt._dllonexit");
    ldr_register_exit(func);
    // ignore warning
    pbegin = NULL;
    pend   = NULL;
    return func;
}

__declspec(noinline)
void __cdecl hook_msvcrt_exit(int exitcode)
{
    dbg_log("[PE Loader]", "call msvcrt.exit");
    ldr_do_exit();
    hook_ExitProcess((UINT)exitcode);
}

__declspec(noinline)
uint __cdecl hook_msvcrt_beginthread(
    void* proc, uint32 stackSize, void* arg
){
    dbg_log("[PE Loader]", "call msvcrt._beginthread");
    HANDLE hThread = stub_CreateThread(
        0, stackSize, proc, arg, 0, NULL, CC_CDECL
    );
    return (uint)hThread;
}

__declspec(noinline)
uint __cdecl hook_msvcrt_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
){
    dbg_log("[PE Loader]", "call msvcrt._beginthreadex");
    HANDLE hThread = stub_CreateThread(
        security, stackSize, proc, arg, flag, tid, CC_STDCALL
    );
    return (uint)hThread;
}

__declspec(noinline)
void __cdecl hook_msvcrt_endthread()
{
    dbg_log("[PE Loader]", "call msvcrt._endthread");
    hook_ExitThread(0);
}

__declspec(noinline)
void __cdecl hook_msvcrt_endthreadex(uint32 code)
{
    dbg_log("[PE Loader]", "call msvcrt._endthreadex");
    hook_ExitThread(code);
}

__declspec(noinline)
int* __cdecl hook_ucrtbase_p_argc()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___argc");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argc;
    }

    // call ucrtbase.__p___argc
#ifdef _WIN64
    uint hash = 0xADF700C69C846081;
    uint key  = 0x164425A411FFA1EC;
#elif _WIN32
    uint hash = 0xDDB2351C;
    uint key  = 0x2F7CAB87;
#endif
    ucrtbase_p_argc_t p_argc = loader->Config.FindAPI(hash, key);
    if (p_argc == NULL)
    {
        return NULL;
    }
    return p_argc();
}

__declspec(noinline)
byte*** __cdecl hook_ucrtbase_p_argv()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___argv");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argv_a;
    }

    // call ucrtbase.__p___argv
#ifdef _WIN64
    uint hash = 0xC64ED1F8F1B1277C;
    uint key  = 0xBDAD98E6C2B6C986;
#elif _WIN32
    uint hash = 0x4B6EA85E;
    uint key  = 0x8E47E1D6;
#endif
    ucrtbase_p_argv_t p_argv = loader->Config.FindAPI(hash, key);
    if (p_argv == NULL)
    {
        return NULL;
    }
    return p_argv();
}

__declspec(noinline)
uint16*** __cdecl hook_ucrtbase_p_wargv()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___wargv");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argv_w;
    }

    // call ucrtbase.__p___wargv
#ifdef _WIN64
    uint hash = 0xC89A5BF3DB908890;
    uint key  = 0xF5124C295B193B2F;
#elif _WIN32
    uint hash = 0x020C7D19;
    uint key  = 0x0FCC5CEA;
#endif
    ucrtbase_p_wargv_t p_wargv = loader->Config.FindAPI(hash, key);
    if (p_wargv == NULL)
    {
        return NULL;
    }
    return p_wargv();
}

__declspec(noinline)
int __cdecl hook_ucrtbase_atexit(void* func)
{
    dbg_log("[PE Loader]", "call ucrtbase._crt_atexit");
    ldr_register_exit(func);
    return 0;
}

__declspec(noinline)
int __cdecl hook_ucrtbase_onexit(void* table, void* func)
{
    dbg_log("[PE Loader]", "call ucrtbase._register_onexit_function");
    ldr_register_exit(func);
    // ignore warning
    table = NULL;
    return 0;
}

__declspec(noinline)
void __cdecl hook_ucrtbase_exit(int exitcode)
{
    dbg_log("[PE Loader]", "call ucrtbase.exit");
    ldr_do_exit();
    hook_ExitProcess((UINT)exitcode);
}

__declspec(noinline)
uint __cdecl hook_ucrtbase_beginthread(
    void* proc, uint32 stackSize, void* arg
){
    dbg_log("[PE Loader]", "call ucrtbase._beginthread");
    HANDLE hThread = stub_CreateThread(
        0, stackSize, proc, arg, 0, NULL, CC_CDECL
    );
    return (uint)hThread;
}

__declspec(noinline)
uint __cdecl hook_ucrtbase_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
){
    dbg_log("[PE Loader]", "call ucrtbase._beginthreadex");
    HANDLE hThread = stub_CreateThread(
        security, stackSize, proc, arg, flag, tid, CC_STDCALL
    );
    return (uint)hThread;
}

__declspec(noinline)
void __cdecl hook_ucrtbase_endthread()
{
    dbg_log("[PE Loader]", "call ucrtbase._endthread");
    hook_ExitThread(0);
}

__declspec(noinline)
void __cdecl hook_ucrtbase_endthreadex(uint32 code)
{
    dbg_log("[PE Loader]", "call ucrtbase._endthreadex");
    hook_ExitThread(code);
}

// if you only parse the command line parameters in the configuration
// and not the current process, the size of the hook function will 
// be larger, but if there are no command line parameters in the 
// configuration, you can use the internal implementation in msvcrt 
// or ucrtbase instead of loading shell32.dll.
void loadCommandLineToArgv()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->argc != 0)
    {
        return;
    }

    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine == NULL)
    {
        return;
    }

    // make sure shell32.dll is loaded
    byte dllName[] = {
        's', 'h', 'e', 'l', 'l', '3', '2', 
        '.', 'd', 'l', 'l', '\x00'
    };
    HMODULE hShell32 = loader->LoadLibraryA(dllName);
    if (hShell32 == NULL)
    {
        return;
    }

    int argc = 0;
    LPWSTR* argv;
    for (;;)
    {
        argv = hook_CommandLineToArgvW(cmdLine, &argc);
        if (argv == NULL)
        {
            break;
        }
        dbg_log("[PE Loader]", "argv pointer: 0x%zX", argv);

        // calculate the buffer size about argv
        // add size of pointer array
        uint size = ((uint)argc + 1) * sizeof(LPWSTR);
        // add each argument string length
        for (LPWSTR* p = argv; *p != NULL; p++)
        {
            size += (strlen_w(*p) + 1) * 2;
        }

        // copy buffer data that we can hide it
        // otherwise, it will in the local heap
        LPWSTR* argv_a = runtime->Memory.Alloc(size);
        LPWSTR* argv_w = runtime->Memory.Alloc(size);
        mem_copy(argv_a, argv, size);
        mem_copy(argv_w, argv, size);

        // fix the string pointers
        uintptr offset = (uintptr)argv_a - (uintptr)argv;
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }
        offset = (uintptr)argv_w - (uintptr)argv;
        for (LPWSTR* p = argv_w; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }

        // convert each argument from UTF16 to ANSI for argv_a
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            LPWSTR ptr = *p;
            ANSI s = runtime->WinBase.UTF16ToANSI(ptr);
            if (s == NULL)
            {
                break;
            }
            strcpy_a((ANSI)ptr, s);
            runtime->Memory.Free(s);
        }
        LPSTR* argv_n = (LPSTR*)argv_a;

        loader->argc   = argc;
        loader->argv_a = argv_n;
        loader->argv_w = argv_w;
        break;
    }

    // free memory from CommandLineToArgvW
    if (argv != NULL)
    {
        loader->LocalFree(argv);
    }
    loader->FreeLibrary(hShell32);
}

__declspec(noinline)
static void pe_entry_point()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call entry point");

    // execute TLS callback list before call EntryPoint.
    ldr_alloc_tls_block();
    ldr_tls_callback(DLL_PROCESS_ATTACH);

    // call EntryPoint usually is main.
    uint exitCode = ((uint(*)())(loader->EntryPoint))();

    // exit process
    hook_ExitProcess(exitCode);
}

__declspec(noinline)
static bool pe_dll_main(DWORD dwReason, bool setExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call DllMain with reason: %d", dwReason);

    // call dll main function
    DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
    HMODULE   hModule = (HMODULE)(loader->PEImage);
    bool retval = dllMain(hModule, dwReason, NULL);
    uint exitCode;
    if (retval)
    {
        exitCode = 0;
    } else {
        exitCode = 1;
    }
    if (setExitCode)
    {
        set_exit_code(exitCode);
    }
    return retval;
}

static void set_exit_code(uint code)
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    *loader->ExitCode = code;

    ldr_unlock_status();
}

static uint get_exit_code()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return 1;
    }

    uint code = *loader->ExitCode;

    if (!ldr_unlock_status())
    {
        return 1;
    }
    return code;
}

__declspec(noinline)
static void set_running(bool run)
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    loader->IsRunning = run;

    ldr_unlock_status();
}

__declspec(noinline)
static bool is_running()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return false;
    }

    bool running = loader->IsRunning;

    if (!ldr_unlock_status())
    {
        return false;
    }
    return running;
}

__declspec(noinline)
static void clean_run_data()
{
    PELoader* loader = getPELoaderPointer();

    // reset command line arguments
    loader->argc   = 0;
    loader->argv_a = NULL;
    loader->argv_w = NULL;

    // reset on exit callback
    loader->on_exit  = NULL;
    loader->num_exit = 0;
}

__declspec(noinline)
static void reset_handler()
{
    PELoader* loader = getPELoaderPointer();

    void* addr = GetFuncAddr(&restart_image);
    HANDLE hThread = loader->CreateThread(NULL, 0, addr, NULL, 0, NULL);
    if (hThread == NULL)
    {
        return;
    }
    loader->CloseHandle(hThread);
}

__declspec(noinline)
static uint restart_image()
{
    dbg_log("[PE Loader]", "restart PE image");

    errno errno = LDR_Exit(0);
    if (errno != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to exit PE image: 0x%X", errno);
    }

    // make sure the running data is clean
    clean_run_data();

    errno = LDR_Execute();
    if (errno != NO_ERROR)
    {
        dbg_log("[PE Loader]", "unexpected exit code: 0x%X", errno);
    }
    return 0;
}

__declspec(noinline)
void* LDR_GetProc(LPSTR name)
{
    if (!ldr_lock())
    {
        SetLastErrno(ERR_LOADER_LOCK);
        return NULL;
    }

    void* address = NULL;
    for (;;)
    {
        if (!is_running())
        {
            SetLastErrno(ERR_LOADER_NOT_RUNNING);
            break;
        }
        address = ldr_process_export(name);
        break;
    }

    if (!ldr_unlock())
    {
        SetLastErrno(ERR_LOADER_UNLOCK);
        return NULL;
    }
    return address;
}

__declspec(noinline)
errno LDR_Execute()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    HANDLE hThread = NULL;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (is_running())
        {
            break;
        }
        errno = ldr_init_mutex();
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!ldr_copy_image())
        {
            errno = ERR_LOADER_COPY_PE_IMAGE;
            break;
        }
        // load library and fix function address
        if (!ldr_process_import())
        {
            errno = ERR_LOADER_PROCESS_IMPORT;
            break;
        }
        // load library and fix function address
        if (!ldr_process_delay_import())
        {
            errno = ERR_LOADER_PROCESS_DELAY_IMPORT;
            break;
        }
        // make callback about DLL_PROCESS_DETACH
        if (loader->IsDLL)
        {
            if (!pe_dll_main(DLL_PROCESS_ATTACH, true))
            {
                errno = ERR_LOADER_CALL_DLL_MAIN;
                break;
            }
            set_running(true);
            break;
        }
        // change the running status
        set_running(true);
        // create thread at entry point
        // TODO no new thread
        void* addr = GetFuncAddr(&pe_entry_point);
        hThread = loader->CreateThread(NULL, 0, addr, NULL, 0, NULL);
        if (hThread == NULL)
        {
            errno = ERR_LOADER_CREATE_MAIN_THREAD;
            set_running(false);
            break;
        }
        break;
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }

    if (hThread != NULL)
    {
        // wait main thread exit
        if (loader->Config.WaitMain)
        {
            loader->WaitForSingleObject(hThread, INFINITE);
            set_running(false);
        }
        loader->CloseHandle(hThread);
    }
    return errno;
}

__declspec(noinline)
errno LDR_Exit(uint exitCode)
{
    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    if (is_running())
    {
        ldr_exit_process(exitCode);
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno LDR_Destroy()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    if (is_running())
    {
        ldr_exit_process(0);
    }

    errno err = NO_ERROR;
    if (loader->Config.NotEraseInstruction)
    {
        DWORD oldProtect;
        if (!adjustPageProtect(loader, &oldProtect) && err == NO_ERROR)
        {
            err = ERR_LOADER_ADJUST_PROTECT;
        }
        if (!recoverPELoaderPointer(loader) && err == NO_ERROR)
        {
            err = ERR_LOADER_RECOVER_INST;
        }
        if (!recoverPageProtect(loader, oldProtect) && err == NO_ERROR)
        {
            err = ERR_LOADER_RECOVER_PROTECT;
        }
    }

    errno errcl = cleanPELoader(loader);
    if (errcl != NO_ERROR && err == NO_ERROR)
    {
        err = errcl;
    }
    return err;
}

// prevent it be linked to other functions.
#pragma optimize("", off)

#pragma warning(push)
#pragma warning(disable: 4189)
static void ldr_epilogue()
{
    byte var = 10;
    return;
}
#pragma warning(pop)

#pragma optimize("", on)
