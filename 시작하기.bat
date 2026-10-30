@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js가 필요합니다. https://nodejs.org 에서 LTS를 설치한 뒤 다시 실행하세요. & pause & exit /b)
node server.mjs
pause
