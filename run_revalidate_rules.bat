@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Revalidate findings in an existing findings__*.json using selected rule IDs.
rem Usage:
rem 1) Set FINDINGS_JSON and model/provider/prices below.
rem 2) Uncomment only the call :run_rule lines you want.
rem 3) Run: .\run_revalidate_rules.bat

set "FINDINGS_JSON=reports\runs\boldbi-server__20260216_155450\findings__boldbi-server__20260216_155450.json"
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

echo.
echo ============================================================
echo Revalidation started
echo Findings JSON: %FINDINGS_JSON%
echo Provider/Model: %LLM_PROVIDER% / %OPENAI_MODEL%
echo ============================================================
echo.

rem -------------------------
rem Uncomment rule(s) to run
rem -------------------------
call :run_rule NFR-DOTNET-001
rem call :run_rule NFR-API-001
rem call :run_rule NFR-API-002
rem call :run_rule NFR-API-003
rem call :run_rule NFR-API-004A
rem call :run_rule NFR-API-004B
rem call :run_rule NFR-API-004C
rem call :run_rule NFR-API-005
rem call :run_rule NFR-API-006
rem call :run_rule NFR-API-007
rem call :run_rule NFR-API-008
rem call :run_rule NFR-API-009
rem call :run_rule NFR-API-010
rem call :run_rule NFR-API-011
rem call :run_rule NFR-API-012
rem call :run_rule NFR-API-013
rem call :run_rule NFR-API-014
rem call :run_rule NFR-API-015
rem call :run_rule NFR-API-016
rem call :run_rule NFR-DOTNET-002
rem call :run_rule NFR-DOTNET-003
rem call :run_rule NFR-DOTNET-003B
rem call :run_rule NFR-DOTNET-004
rem call :run_rule NFR-DOTNET-005
rem call :run_rule NFR-DOTNET-006
rem call :run_rule NFR-DOTNET-007
rem call :run_rule NFR-DOTNET-008
rem call :run_rule NFR-DOTNET-009
rem call :run_rule NFR-DOTNET-010
rem call :run_rule NFR-DOTNET-011
rem call :run_rule NFR-DOTNET-012
rem call :run_rule NFR-DOTNET-013
rem call :run_rule NFR-DOTNET-014
rem call :run_rule NFR-DOTNET-015
rem call :run_rule NFR-DOTNET-016
rem call :run_rule NFR-DOTNET-017
rem call :run_rule NFR-DOTNET-018
rem call :run_rule NFR-DOTNET-019
rem call :run_rule NFR-DOTNET-020
rem call :run_rule NFR-DOTNET-021
rem call :run_rule NFR-DOTNET-022
rem call :run_rule NFR-FE-001
rem call :run_rule NFR-FE-002
rem call :run_rule NFR-FE-003
rem call :run_rule NFR-FE-004
rem call :run_rule NFR-FE-005A
rem call :run_rule NFR-FE-005B
rem call :run_rule NFR-FE-006
rem call :run_rule NFR-FE-007
rem call :run_rule NFR-FE-008
rem call :run_rule NFR-FE-009
rem call :run_rule NFR-FE-010
rem call :run_rule NFR-FE-011
rem call :run_rule NFR-FE-012
rem call :run_rule NFR-FE-013
rem call :run_rule NFR-FE-014
rem call :run_rule NFR-FE-015
rem call :run_rule NFR-FE-016
rem call :run_rule NFR-RAZOR-001
rem call :run_rule NFR-RAZOR-002
rem call :run_rule NFR-RAZOR-003
rem call :run_rule NFR-RAZOR-004
rem call :run_rule NFR-RAZOR-004B
rem call :run_rule NFR-RAZOR-005

echo.
echo ============================================================
echo Revalidation finished
echo ============================================================
echo.
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
