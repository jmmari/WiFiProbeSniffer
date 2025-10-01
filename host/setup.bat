@echo off
echo [*] Setting up Python environment...

REM Create venv if it does not exist
if not exist venv (
    python -m venv venv
)

REM Activate venv
call venv\Scripts\activate

REM Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [*] Setup complete!
echo.
echo Usage:
echo   Live sniffing : venv\Scripts\python serial_probe_viewer.py COM3 115200
echo   Playback log  : venv\Scripts\python serial_probe_viewer.py probes_log_1.jsonl
echo.
pause
