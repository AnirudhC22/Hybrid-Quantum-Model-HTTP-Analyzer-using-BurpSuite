@echo off
echo ============================================
echo  Web Attack Detector - Windows Launcher
echo ============================================
echo.

if "%1"=="train" goto train
if "%1"=="train-fast" goto train_fast
if "%1"=="test" goto test
if "%1"=="server" goto server
if "%1"=="server-noqml" goto server_noqml
goto help

:train
echo [Training] Full training with QML...
python train.py
goto end

:train_fast
echo [Training] Fast training (no QML)...
python train.py --skip-qml
goto end

:test
echo [Testing] Running detection tests...
python tests\test_detection.py
goto end

:server
echo [Server] Starting API server with QML...
set USE_QML=true
python api_server.py
goto end

:server_noqml
echo [Server] Starting API server without QML...
set USE_QML=false
python api_server.py
goto end

:help
echo Usage:
echo   run.bat train-fast     ^<-- Step 1: Train models
echo   run.bat test           ^<-- Step 2: Verify tests pass
echo   run.bat server-noqml   ^<-- Step 3: Start dashboard
echo.

:end
