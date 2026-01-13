@echo off
setlocal ENABLEDELAYEDEXPANSION

rem Auto-compiles scanner.cpp into scanner.exe.
rem Tries (in order): g++ (MinGW), clang++, clang, MSVC (found via vswhere/vcvarsall).

set SRC=scanner.cpp
set OUT=scanner.exe

if not exist "%SRC%" (
    echo Source file %SRC% not found.
    exit /b 1
)

call :build_with_gpp
if %errorlevel%==0 goto done

call :build_with_clangpp
if %errorlevel%==0 goto done

call :build_with_clang
if %errorlevel%==0 goto done

call :build_with_msvc
if %errorlevel%==0 goto done

echo No supported C++ compiler found. Install MinGW-w64, LLVM/clang, or Visual Studio Build Tools (C++ workload).
exit /b 1

:done
echo Build succeeded: %OUT%
exit /b 0

:build_with_gpp
where g++ >nul 2>&1 || exit /b 1
echo Detected g++. Building with MinGW g++...
g++ "%SRC%" -std=c++17 -O2 -o "%OUT%" -lws2_32 -lcomctl32 -luser32 -lgdi32
if errorlevel 1 (
    echo g++ build failed.
    exit /b 1
)
exit /b 0

:build_with_clangpp
where clang++ >nul 2>&1 || exit /b 1
echo Detected clang++. Building...
clang++ "%SRC%" -std=c++17 -O2 -o "%OUT%" -lws2_32 -lcomctl32 -luser32 -lgdi32
if errorlevel 1 (
    echo clang++ build failed.
    exit /b 1
)
exit /b 0

:build_with_clang
where clang >nul 2>&1 || exit /b 1
echo Detected clang. Building in g++ driver mode...
clang --driver-mode=g++ "%SRC%" -std=c++17 -O2 -o "%OUT%" -lws2_32 -lcomctl32 -luser32 -lgdi32
if errorlevel 1 (
    echo clang build failed.
    exit /b 1
)
exit /b 0

:build_with_msvc
rem Attempt to locate MSVC via vswhere and run vcvarsall.bat to enable cl.
set VSPATH=
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist %VSWHERE% (
    for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
)
if "%VSPATH%"=="" (
    rem Try common Enterprise/Community preview path if vswhere missing.
    if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
        set VSPATH=C:\Program Files\Microsoft Visual Studio\2022\BuildTools
    )
)
if "%VSPATH%"=="" exit /b 1

set VCBAT=%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat
if not exist "%VCBAT%" exit /b 1

echo Detected MSVC at %VSPATH%. Initializing environment...
call "%VCBAT%" x64 >nul
cl /nologo /std:c++17 /EHsc /O2 "%SRC%" ws2_32.lib comctl32.lib user32.lib gdi32.lib /Fe:%OUT%
if errorlevel 1 (
    echo cl build failed.
    exit /b 1
)
exit /b 0
