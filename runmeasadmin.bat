@echo off
:: RunMeAsAdmin.bat
:: Written by Arran Holmes 40454196
:: Designed to avoid ExecutionPolicy issues

powershell.exe -ExecutionPolicy Bypass -File "%~dp0/collect.ps1"
pause
