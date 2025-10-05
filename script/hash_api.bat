@echo off

echo =====================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/GRT-Develop
echo =====================================================================
echo.

echo ------------------------x64------------------------
hash_api -fmt 64 -conc -mod "kernel32.dll" -func VirtualAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -func VirtualFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -func VirtualProtect
hash_api -fmt 64 -conc -mod "kernel32.dll" -func LoadLibraryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -func FreeLibrary
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -func CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -func ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -func FlushInstructionCache
hash_api -fmt 64 -conc -mod "kernel32.dll" -func CreateMutexA
hash_api -fmt 64 -conc -mod "kernel32.dll" -func ReleaseMutex
hash_api -fmt 64 -conc -mod "kernel32.dll" -func WaitForSingleObject
hash_api -fmt 64 -conc -mod "kernel32.dll" -func CreateFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -func CloseHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetCommandLineA
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetCommandLineW
hash_api -fmt 64 -conc -mod "kernel32.dll" -func LocalFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetStdHandle

hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetCommandLineA
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetCommandLineW
hash_api -fmt 64 -conc -mod "shell32.dll"  -func CommandLineToArgvW
hash_api -fmt 64 -conc -mod "kernel32.dll" -func GetStdHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -func CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -func ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -func ExitProcess
hash_api -fmt 64 -conc -mod "ntdll.dll"    -func RtlExitUserThread
hash_api -fmt 64 -conc -mod "ntdll.dll"    -func RtlExitUserProcess
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func __getmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func __wgetmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func atexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _onexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _dllonexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _Exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _cexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _c_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func quick_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _amsg_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _o_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _beginthread
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _beginthreadex
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _endthread
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -func _endthreadex
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___argc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___argv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___wargv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _crt_atexit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _crt_at_quick_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _register_onexit_function
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _Exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _cexit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _c_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func quick_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _beginthread
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _beginthreadex
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _endthread
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _endthreadex

hash_api -fmt 64 -conc -mod "shell32.dll" -func CommandLineToArgvW

hash_api -fmt 64 -conc -mod "msvcrt.dll" -func __getmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func __wgetmainargs

hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___argc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___argv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func __p___wargv
echo.

echo ------------------------x86------------------------
hash_api -fmt 32 -conc -mod "kernel32.dll" -func VirtualAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -func VirtualFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -func VirtualProtect
hash_api -fmt 32 -conc -mod "kernel32.dll" -func LoadLibraryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -func FreeLibrary
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -func CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -func ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -func FlushInstructionCache
hash_api -fmt 32 -conc -mod "kernel32.dll" -func CreateMutexA
hash_api -fmt 32 -conc -mod "kernel32.dll" -func ReleaseMutex
hash_api -fmt 32 -conc -mod "kernel32.dll" -func WaitForSingleObject
hash_api -fmt 32 -conc -mod "kernel32.dll" -func CreateFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -func CloseHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetCommandLineA
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetCommandLineW
hash_api -fmt 32 -conc -mod "kernel32.dll" -func LocalFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetStdHandle

hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetCommandLineA
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetCommandLineW
hash_api -fmt 32 -conc -mod "shell32.dll"  -func CommandLineToArgvW
hash_api -fmt 32 -conc -mod "kernel32.dll" -func GetStdHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -func CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -func ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -func ExitProcess
hash_api -fmt 32 -conc -mod "ntdll.dll"    -func RtlExitUserThread
hash_api -fmt 32 -conc -mod "ntdll.dll"    -func RtlExitUserProcess
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func __getmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func __wgetmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func atexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _onexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _dllonexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _Exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _cexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _c_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func quick_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _amsg_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _o_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _beginthread
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _beginthreadex
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _endthread
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -func _endthreadex
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___argc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___argv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___wargv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _crt_atexit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _crt_at_quick_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _register_onexit_function
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _Exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _cexit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _c_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func quick_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _beginthread
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _beginthreadex
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _endthread
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _endthreadex

hash_api -fmt 32 -conc -mod "shell32.dll" -func CommandLineToArgvW

hash_api -fmt 32 -conc -mod "msvcrt.dll" -func __getmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func __wgetmainargs

hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___argc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___argv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func __p___wargv
echo.

pause
