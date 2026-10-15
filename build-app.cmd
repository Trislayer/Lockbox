@echo off
rem Build the Lockbox desktop app from any folder. Options: --skip-checks
node "%~dp0desktop\build-app.js" %*
