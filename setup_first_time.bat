@echo off
setlocal EnableExtensions

cd /d "%~dp0"

echo [NFR Audit Workbench] First-time setup started...

where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python is not installed or not available in PATH.
  exit /b 1
)

for /f "delims=" %%v in ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"') do set PY_VER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PY_VER%") do (
  set PY_MAJOR=%%a
  set PY_MINOR=%%b
)
if %PY_MAJOR% LSS 3 (
  echo ERROR: Python 3.10+ is required. Found %PY_VER%.
  exit /b 1
)
if %PY_MAJOR% EQU 3 if %PY_MINOR% LSS 10 (
  echo ERROR: Python 3.10+ is required. Found %PY_VER%.
  exit /b 1
)

if not exist ".venv\" (
  echo Creating virtual environment at .venv ...
  python -m venv .venv
  if errorlevel 1 (
    echo ERROR: Failed to create virtual environment.
    exit /b 1
  )
)

echo Installing Python dependencies...
call .venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 (
  echo ERROR: Failed to upgrade pip.
  exit /b 1
)
call .venv\Scripts\python.exe -m pip install requests python-dotenv
if errorlevel 1 (
  echo ERROR: Failed to install Python dependencies.
  exit /b 1
)

where rg >nul 2>&1
if errorlevel 1 (
  echo ripgrep (rg) not found. Attempting installation via winget...
  where winget >nul 2>&1
  if errorlevel 1 (
    echo WARNING: winget not found. Install ripgrep manually for faster scans.
  ) else (
    winget install --id BurntSushi.ripgrep.MSVC -e --source winget --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
      echo WARNING: ripgrep installation failed. Scanner fallback mode will still work.
    )
  )
)

if not exist "reports\" mkdir reports
if not exist "reports\.gitkeep" type nul > reports\.gitkeep

echo.
echo Setup complete.
echo Activate environment: .venv\Scripts\activate
echo Run scanner:         python nfr_scan.py --path C:\development\my-service
echo Start UI:            python ui\run_ui.py
echo Open UI:             http://127.0.0.1:8787/ui/index.html
exit /b 0
