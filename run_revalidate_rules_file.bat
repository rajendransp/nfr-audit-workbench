@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Revalidate findings using rule IDs from a text file (one rule per line).
rem Rules file behavior:
rem - Empty lines are ignored
rem - Lines starting with # are treated as comments and ignored
rem - All other lines are treated as rule IDs (example: NFR-DOTNET-001)
rem
rem Usage:
rem   .\run_revalidate_rules_file.bat
rem   .\run_revalidate_rules_file.bat path\to\findings__x.json
rem   .\run_revalidate_rules_file.bat path\to\findings__x.json path\to\my_rules.txt
rem   .\run_revalidate_rules_file.bat path\to\findings__x.json AUTO
rem Backward-compatible:
rem   .\run_revalidate_rules_file.bat path\to\my_rules.txt

set "DEFAULT_FINDINGS_JSON=reports\findings.json"
set "DEFAULT_RULES_FILE=revalidate_rules.txt"
set "FINDINGS_JSON=%~1"
set "RULES_FILE=%~2"
set "AUTO_RULES=0"
set "TEMP_RULES_FILE="

if "%FINDINGS_JSON%"=="" (
  set "FINDINGS_JSON=%DEFAULT_FINDINGS_JSON%"
  if "%RULES_FILE%"=="" set "RULES_FILE=%DEFAULT_RULES_FILE%"
) else (
  rem If only one arg is provided and it looks like a rules text file, treat it as RULES_FILE.
  if "%RULES_FILE%"=="" (
    if /i "%~x1"==".txt" (
      set "RULES_FILE=%~1"
      set "FINDINGS_JSON=%DEFAULT_FINDINGS_JSON%"
    ) else (
      set "RULES_FILE=%DEFAULT_RULES_FILE%"
    )
  )
)

if /i "%RULES_FILE%"=="AUTO" (
  set "AUTO_RULES=1"
  set "RULES_FILE="
)

set "LLM_PROVIDER=openai"
set "OPENAI_MODEL=gpt-4.1"
set "MAX_LLM=50"
set "LLM_WORKERS=4"
set "REVALIDATE_ONLY_NON_ISSUE=true"

rem Optional price inputs for cost estimate (per 1M tokens)
set "PRICE_INPUT=2"
set "PRICE_CACHED_INPUT=0.5"
set "PRICE_OUTPUT=8"

if not exist "%FINDINGS_JSON%" (
  echo [ERROR] Findings JSON not found: %FINDINGS_JSON%
  exit /b 1
)

if "%RULES_FILE%"=="" set "AUTO_RULES=1"
if %AUTO_RULES%==0 (
  if not exist "%RULES_FILE%" (
    echo [WARN] Rules file not found: %RULES_FILE%
    echo [WARN] Falling back to AUTO rules from findings JSON.
    set "AUTO_RULES=1"
  )
)

if %AUTO_RULES%==1 (
  set "TEMP_RULES_FILE=%TEMP%\nfr_revalidate_rules_%RANDOM%_%RANDOM%.txt"
  powershell -NoProfile -Command ^
    "$p='%FINDINGS_JSON%'; $j=Get-Content $p -Raw | ConvertFrom-Json; $ids=@($j.findings | ForEach-Object { $_.rule_id } | Where-Object { $_ } | Sort-Object -Unique); Set-Content -Path '%TEMP_RULES_FILE%' -Value ($ids -join [Environment]::NewLine) -Encoding UTF8"
  if errorlevel 1 (
    echo [ERROR] Failed to derive rules from findings JSON: %FINDINGS_JSON%
    exit /b 1
  )
  set "RULES_FILE=%TEMP_RULES_FILE%"
)

echo.
echo ============================================================
echo Revalidation started (rules file mode)
echo Findings JSON: %FINDINGS_JSON%
echo Rules file: %RULES_FILE%
echo Provider/Model: %LLM_PROVIDER% / %OPENAI_MODEL%
echo ============================================================
echo.

set "RULE_COUNT=0"
for /f "usebackq delims=" %%L in ("%RULES_FILE%") do (
  set "RULE_LINE=%%L"
  for /f "tokens=* delims= " %%A in ("!RULE_LINE!") do set "RULE_LINE=%%A"
  if not "!RULE_LINE!"=="" (
    if not "!RULE_LINE:~0,1!"=="#" (
      set /a RULE_COUNT+=1
      call :run_rule "!RULE_LINE!"
    )
  )
)

echo.
echo Processed rules: %RULE_COUNT%
echo ============================================================
echo Revalidation finished
echo ============================================================
echo.
if defined TEMP_RULES_FILE (
  if exist "%TEMP_RULES_FILE%" del /q "%TEMP_RULES_FILE%" >nul 2>&1
)
exit /b 0

:run_rule
set "RULE_ID=%~1"
if "%RULE_ID%"=="" exit /b 0

echo ------------------------------------------------------------
echo Revalidating %RULE_ID%
echo ------------------------------------------------------------

if /i "%REVALIDATE_ONLY_NON_ISSUE%"=="true" (
  set "REVALIDATE_MODE_ARG=--revalidate-only-non-issue"
) else (
  set "REVALIDATE_MODE_ARG=--no-revalidate-only-non-issue"
)

python nfr_scan.py --revalidate-findings-json "%FINDINGS_JSON%" --revalidate-rule-id "%RULE_ID%" %REVALIDATE_MODE_ARG% --llm-provider "%LLM_PROVIDER%" --openai-model "%OPENAI_MODEL%" --max-llm %MAX_LLM% --llm-workers %LLM_WORKERS% --auto-continue-batches --price-input-per-1m %PRICE_INPUT% --price-cached-input-per-1m %PRICE_CACHED_INPUT% --price-output-per-1m %PRICE_OUTPUT%

if errorlevel 1 (
  echo [WARN] Revalidation failed for %RULE_ID%
) else (
  echo [OK] Revalidation completed for %RULE_ID%
)
exit /b 0
