@echo off
@echo OS Detection Test
@echo =================
@echo.
@echo Testing OS detection for various domains...
@echo.

echo Testing google.com:
echo google.com | py domain_scanner.py
@echo.
pause