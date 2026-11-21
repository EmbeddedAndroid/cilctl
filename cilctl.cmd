@echo off
rem SPDX-License-Identifier: BSD-2-Clause
rem cilctl for Windows: runs the cilctl script next to this file
setlocal
where py 1>NUL 2>NUL
if %ERRORLEVEL%==0 (
  py -3 "%~dp0cilctl" %*
) else (
  python "%~dp0cilctl" %*
)
exit /b %ERRORLEVEL%
