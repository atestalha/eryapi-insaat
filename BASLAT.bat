@echo off
chcp 65001 >nul
title ER Yapi Insaat - Site ve Yonetim Paneli
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js kurulu degil. https://nodejs.org adresinden LTS surumunu kurun. & pause & exit /b)
if not exist node_modules (echo Gerekli dosyalar kuruluyor, bir kez yapilir... & call npm install --omit=dev)
start "" http://localhost:3000
start "" http://localhost:3000/admin
node server.js
pause
