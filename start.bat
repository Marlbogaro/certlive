@echo off
REM =====================================================================
REM  start.bat - Lance certlive directement apres telechargement du projet
REM
REM  Ce script :
REM    1. Verifie que Python est installe
REM    2. Cree (si besoin) un environnement virtuel dans .venv
REM    3. Installe les dependances listees dans requirements.txt
REM    4. Lance certlive.py en passant les eventuels arguments
REM
REM  Utilisation :
REM      start.bat                  (affiche tous les domaines)
REM      start.bat -k paypal        (filtre sur un mot-cle)
REM      start.bat -o domains.txt   (enregistre dans un fichier)
REM =====================================================================

setlocal

cd /d "%~dp0"

REM --- 1. Verifier la presence de Python -------------------------------
where python >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo Telechargez-le sur https://www.python.org/downloads/ puis relancez ce script.
    pause
    exit /b 1
)

REM --- 2. Creer l'environnement virtuel si necessaire ------------------
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creation de l'environnement virtuel .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERREUR] Impossible de creer l'environnement virtuel.
        pause
        exit /b 1
    )
)

REM --- 3. Installer les dependances ------------------------------------
echo [INFO] Installation des dependances ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERREUR] Echec de l'installation des dependances.
    pause
    exit /b 1
)

REM --- 4. Lancer certlive ----------------------------------------------
echo [INFO] Demarrage de certlive ...
echo.
".venv\Scripts\python.exe" certlive.py %*

endlocal
