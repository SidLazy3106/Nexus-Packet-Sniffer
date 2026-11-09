@echo off
rem Double-click to preview the NEXUS website. Needs Node.js. Close this window to stop.
cd /d "%~dp0"
echo Starting the preview on http://127.0.0.1:4173 ...
start "" "http://127.0.0.1:4173"
node scripts\dev.cjs
pause
