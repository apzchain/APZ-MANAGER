@echo off
set /p VT=VirusTotal API key (blank to skip):
if not "%VT%"=="" setx APZ_VT_API_KEY "%VT%"
set /p HA=Hybrid Analysis API key (blank to skip):
if not "%HA%"=="" setx APZ_HA_API_KEY "%HA%"
set /p MD=MetaDefender Cloud API key (blank to skip):
if not "%MD%"=="" setx APZ_MD_API_KEY "%MD%"
echo.
echo Keys saved for future Windows sessions. Restart APZ Manager.
pause
