# SOC Wazuh Lab

Laboratorio personal para practicar detección y respuesta ante ataques en un entorno
segmentado con **pfSense + Wazuh + Sysmon**.

El objetivo principal es simular distintos escenarios alineados con **MITRE ATT&CK**
y validar qué tan bien los detecta Wazuh (reglas oficiales + reglas locales).

## Arquitectura del laboratorio

- **Firewall / router:** pfSense
  - Segmentación en redes OPT1 (Windows), OPT2 (Wazuh), OPT3 (Kali) y LAN.
- **SIEM / XDR:** Wazuh Server + Dashboard.
- **Endpoint Windows 11:** `DESKTOP-IS5MQHK`
  - Agente Wazuh.
  - Sysmon con configuración personalizada.
- **Atacante:** Kali Linux en OPT3.

Más detalles en:

- [`arquitectura-lab.md`](./arquitectura-lab.md)
- [`pfsense-firewall.md`](./pfsense-firewall.md)

## Fases del proyecto

La documentación principal está en la carpeta [`docs/`](./docs):
1. **Fase 1 – Base endurecida y calidad de señal en Wazuh**  
   - Hardening básico de Windows 11 y pfSense.  
   - Instalación y configuración de Sysmon y Wazuh Agent.  
   - Revisión de la “calidad de señal” (qué eventos llegan y cuáles son ruido).

2. **Fase 2 – Plan de pruebas y resultados**  
   - Diseño de casos de prueba por técnica ATT&CK (PowerShell, Run keys, servicios, discovery…).  
   - Creación de reglas locales de Wazuh (`100100–100150`).  
   - Validación de cada técnica de forma aislada.

3. **Fase 3 – Escenario APT encadenado**  
   - Simulación de un atacante en Kali con credenciales de admin local.  
   - Uso de `impacket-psexec`, `schtasks`, `net user`, `systeminfo`, etc.  
   - Validación de la cadena completa:
     - T1082, T1016, T1087 (Discovery)  
     - T1053.005 (Scheduled Task)  
     - T1105 (Ingress Tool Transfer)  
     - T1059.* (Command & Scripting Interpreter)

4. **Fase 4 – Trabajo futuro y mejoras propuestas**  
   - Ideas para ampliar el lab: más técnicas, más plataformas, correlación avanzada y SOAR ligero.

## Configuraciones y scripts

- **Configs Wazuh / Sysmon / pfSense:** en [`configs/`](./configs).  
  Contiene ejemplos de `local_rules.xml`, configuración de Sysmon y export de reglas del firewall.

- **Scripts de prueba:** en [`scripts/`](./scripts).  
  Incluye los payloads usados en las fases 2 y 3:
  - `fase3-recon-persist.cmd`
  - `fase3-recon-persist-remote.cmd`
  - Scripts de persistencia y pruebas de PowerShell de la Fase 2.

## Imágenes y capturas

Las capturas de pantalla que acompañan a la documentación están en
[`assets/screenshots`](./assets/screenshots).

En los `.md` se referencian con rutas relativas, por ejemplo:

```markdown
![Threat Hunting – T1105 y T1059](../assets/screenshots/fase3-threat-hunting-T1105-T1059.png)
```

