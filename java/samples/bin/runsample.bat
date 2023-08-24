@echo off

setlocal
set ORGDIR=%CD%
cd %~dp0..
set BASEDIR=%CD%
cd %ORGDIR%
if exist "%BASEDIR%\target" (
    set CLASSPATH=%BASEDIR%\target\samples.jar;%BASEDIR%\target\lib\*
) else (
    set CLASSPATH=%BASEDIR%\lib\*
)

if not "%JAVA%" == "" goto start
if exist "%JAVA_HOME%\bin\java.exe" set JAVA=%JAVA_HOME%\bin\java.exe
if "%JAVA%" == "" set JAVA=java

:start
set main=se.minaombud.samples.cli.CliDriver
if "%1" == "EndUserSample" (
    set main=se.minaombud.samples.%1
    shift
)
if "%1" == "SystemServiceSample" (
    set main=se.minaombud.samples.%1
    shift
)

if not "%MINA_OMBUD_SAMPLE_DATA%" == "" goto run
if exist "%BASEDIR%\..\..\data" set MINA_OMBUD_SAMPLE_DATA=%BASEDIR%\..\..\data
if exist "%BASEDIR%\..\data" set MINA_OMBUD_SAMPLE_DATA=%BASEDIR%\..\data
if exist "%BASEDIR%\data" set MINA_OMBUD_SAMPLE_DATA=%BASEDIR%\data

:run
%JAVA% %JAVA_OPTS% -cp %CLASSPATH% %main% %*
set ERROR_CODE=%ERRORLEVEL%
exit /B %ERROR_CODE%
