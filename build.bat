@echo off
rem Build WebShindan.exe into dist\ (PyInstaller required: python -m pip install pyinstaller)
cd /d "%~dp0"
python -m PyInstaller --noconfirm --onefile --windowed --name WebShindan --distpath dist --workpath build --specpath build main.py
if errorlevel 1 (echo BUILD FAILED) else (echo BUILD OK: dist\WebShindan.exe)
pause
