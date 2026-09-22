@echo off
REM Double-click this file to launch RansomTrace's web app.
REM No command line knowledge needed - it opens in your web browser.

cd /d "%~dp0"

if not exist ".venv\Scripts\streamlit.exe" (
    echo Setting up RansomTrace for the first time - this only happens once...
    py -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
    pip install -e .
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo Starting RansomTrace... a browser tab will open automatically.
echo Close this window when you are done to stop the app.
echo.

streamlit run ransomtrace\validation\web_review.py

pause
