@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ===================== clean old files ====================
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "cutter\Release"
rd /S /Q "cutter\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ======================== generate ========================
MSBuild.exe GRT-PELoader.sln /t:builder /p:Configuration=Release /p:Platform=x64
MSBuild.exe GRT-PELoader.sln /t:builder /p:Configuration=Release /p:Platform=x86
MSBuild.exe GRT-PELoader.sln /t:cutter /p:Configuration=Release /p:Platform=x64
MSBuild.exe GRT-PELoader.sln /t:cutter /p:Configuration=Release /p:Platform=x86

echo =============== extract PE Loader shellcode ==============
del /S /Q dist

cd builder
echo --------extract shellcode for x64--------
"..\x64\Release\builder.exe"
echo --------extract shellcode for x86--------
"..\Release\builder.exe"
cd ..

cd cutter
echo ----------cut PE Loader for x64----------
"..\x64\Release\cutter.exe"
echo ----------cut PE Loader for x86----------
"..\Release\cutter.exe"
cd ..

echo =================== clean output files ===================
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "cutter\Release"
rd /S /Q "cutter\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ================ generate assembly module ================
go run dump.go

echo ==========================================================
echo                  build shellcode finish!
echo ==========================================================
