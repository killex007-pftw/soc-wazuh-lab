@echo off
REM Fase 3 – Reconocimiento y Persistencia Remota
REM Técnicas: T1105 (Ingress Tool Transfer), T1053.005 (Scheduled Task)

REM Información del sistema
systeminfo >> %TEMP%\fase3-recon-remote.txt
whoami /all >> %TEMP%\fase3-recon-remote.txt
ipconfig /all >> %TEMP%\fase3-recon-remote.txt
arp -a >> %TEMP%\fase3-recon-remote.txt
netstat -ano >> %TEMP%\fase3-recon-remote.txt
route print >> %TEMP%\fase3-recon-remote.txt

REM Comando para obtener usuarios
net user >> %TEMP%\fase3-recon-remote.txt

REM Crear tarea programada desde consola remota para persistencia
schtasks /create ^
  /sc once ^
  /tn "Fase3_Remote_T1053" ^
  /tr "C:\\Windows\\System32\\notepad.exe" ^
  /st 23:59 ^
  /f