:: This method is not recommended, and we recommend you use the `start.sh` file with WSL instead.
@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: Get the directory of the current script
SET "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%" || exit /b

:: Add conditional Playwright browser installation
IF /I "%WEB_LOADER_ENGINE%" == "playwright" (
    IF "%PLAYWRIGHT_WS_URL%" == "" (
        echo Installing Playwright browsers...
        playwright install chromium
        playwright install-deps chromium
    )

    python -c "import nltk; nltk.download('punkt_tab')"
)

SET "KEY_FILE=.webui_secret_key"
IF NOT "%WEBUI_SECRET_KEY_FILE%" == "" (
    SET "KEY_FILE=%WEBUI_SECRET_KEY_FILE%"
)

IF "%PORT%"=="" SET PORT=8080
IF "%HOST%"=="" SET HOST=0.0.0.0
SET "WEBUI_SECRET_KEY=%WEBUI_SECRET_KEY%"
SET "WEBUI_JWT_SECRET_KEY=%WEBUI_JWT_SECRET_KEY%"

:: Check if WEBUI_SECRET_KEY and WEBUI_JWT_SECRET_KEY are not set
IF "%WEBUI_SECRET_KEY% %WEBUI_JWT_SECRET_KEY%" == " " (
    echo Loading WEBUI_SECRET_KEY from file, not provided as an environment variable.

    IF NOT EXIST "%KEY_FILE%" (
        echo Generating WEBUI_SECRET_KEY
        :: Generate a random value to use as a WEBUI_SECRET_KEY in case the user didn't provide one
        SET /p WEBUI_SECRET_KEY=<nul
        FOR /L %%i IN (1,1,12) DO SET /p WEBUI_SECRET_KEY=<!random!>>%KEY_FILE%
        echo WEBUI_SECRET_KEY generated
    )

    echo Loading WEBUI_SECRET_KEY from %KEY_FILE%
    SET /p WEBUI_SECRET_KEY=<%KEY_FILE%
)

:: Execute uvicorn
SET "WEBUI_SECRET_KEY=%WEBUI_SECRET_KEY%"
IF "%UVICORN_WORKERS%"=="" SET UVICORN_WORKERS=1
IF "%CORS_ALLOW_ORIGIN%"=="" SET CORS_ALLOW_ORIGIN=http://localhost:5173;http://localhost:8080
SET SSL_ARGS=
IF /I "%ENABLE_HTTPS%"=="true" (
    IF NOT "%HTTPS_PORT%"=="" SET PORT=%HTTPS_PORT%
    IF NOT "%HTTPS_CERT_PATH%"=="" IF NOT "%HTTPS_KEY_PATH%"=="" (
        IF EXIST "%HTTPS_CERT_PATH%" IF EXIST "%HTTPS_KEY_PATH%" (
            ECHO Starting with HTTPS on port %PORT%
            SET SSL_ARGS=--ssl-certfile "%HTTPS_CERT_PATH%" --ssl-keyfile "%HTTPS_KEY_PATH%"
        ) ELSE (
            ECHO ENABLE_HTTPS set but cert/key files not found, starting without SSL.
        )
    )
)

uvicorn open_webui.main:app --host "%HOST%" --port "%PORT%" --forwarded-allow-ips '*' --workers %UVICORN_WORKERS% %SSL_ARGS% --ws auto
