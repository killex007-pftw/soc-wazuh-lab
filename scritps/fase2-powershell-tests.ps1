# Fase 2 – Powershell Tests
# Técnicas: T1082, T1087, T1053.005

# Recolectar información del sistema
systeminfo | Out-File -Append "$env:TEMP\fase2-recon.txt"
whoami /all | Out-File -Append "$env:TEMP\fase2-recon.txt"
ipconfig /all | Out-File -Append "$env:TEMP\fase2-recon.txt"
arp -a | Out-File -Append "$env:TEMP\fase2-recon.txt"
netstat -ano | Out-File -Append "$env:TEMP\fase2-recon.txt"
route print | Out-File -Append "$env:TEMP\fase2-recon.txt"

# Añadir usuario y credenciales de la máquina
net user | Out-File -Append "$env:TEMP\fase2-recon.txt"

# Creación de tarea programada para persistencia
schtasks /create /sc once /tn "Fase2_T1053_Persist" /tr "notepad.exe" /st 23:59 /f
