## 4. Trabajo Futuro y Mejoras Propuestas

En esta fase se abordan las posibles mejoras y la expansión del laboratorio de detección. El trabajo futuro se enfoca en la ampliación de la cobertura de las técnicas MITRE ATT&CK, la mejora de la detección de eventos, la reducción de falsos positivos, y la automatización de respuestas ante incidentes.

### 1. Ampliación de la cobertura ATT&CK

En este trabajo se han priorizado técnicas de **ejecución**, **persistencia**, **descubrimiento** e **ingress tool transfer** en un entorno Windows. Como trabajo futuro, sería interesante:

- Incorporar técnicas adicionales de **lateral movement** (por ejemplo, uso de WMI, RDP, SMB).
    
- Extender la monitorización a **otros sistemas operativos** (Linux servers, contenedores, etc.).
    
- Añadir detecciones específicas para herramientas de post-explotación habituales (PsExec, WMIC, herramientas de AD, etc.), siempre mapeadas a ATT&CK.

### 2. Afinado de umbrales y reducción de falsos positivos

La mejora continua del sistema de detección debe involucrar el ajuste de umbrales de alertas para evitar falsos positivos. Esto incluiría:

- Revisar y ajustar las reglas para que las alertas sean más precisas, especialmente en eventos que se producen en entornos de pruebas y no en un entorno real de ataque.
    
- Filtrar alertas que se activan con demasiada frecuencia, como el caso de "A process was created" (rule id 67027), que se dispara por actividades normales del sistema, como el uso de comandos como `systeminfo`, `ipconfig` o `whoami`.

### 3. Correlación avanzada y detección basada en comportamiento

Las soluciones actuales en Wazuh pueden beneficiarse de una mayor correlación entre eventos, especialmente para detectar actividades anómalas que no se pueden identificar con reglas simples. Se proponen las siguientes acciones:

- Implementar un sistema de correlación basado en el comportamiento, donde se monitoreen los patrones de acceso y uso de los sistemas, además de los ataques conocidos.
    
- Integrar detección de **anomalías** que puedan señalar actividades sospechosas basadas en el análisis del comportamiento histórico del usuario.

### 4. Integración con otras fuentes de telemetría

El laboratorio de detección se puede beneficiar enormemente de integrar datos adicionales provenientes de diferentes fuentes de telemetría. Para este trabajo futuro, se propone:

- **Suricata/Zeek**: Integrar datos de tráfico de red para complementar las alertas generadas en el endpoint. Esto permitirá detectar ataques de Command and Control (C2), escaneo de puertos, y otros eventos relevantes desde la red.
    
- **Logs de aplicaciones**: Incorporar los logs de aplicaciones como **SQL Server** y **Active Directory** para tener visibilidad completa de lo que está ocurriendo tanto en los servidores como en la red.

### 5. Automatización de respuestas (SOAR ligero)

El paso siguiente es automatizar ciertas respuestas ante incidentes para reducir el tiempo de reacción ante un ataque. Algunas propuestas incluyen:

- Implementar **playbooks** de SOAR (Security Orchestration, Automation, and Response) para la automatización de tareas simples, como la desconexión de máquinas comprometidas, la ejecución de scripts de remediación o la recopilación de información.
    
- Integrar **Slack** o **Teams** para alertar al equipo de seguridad automáticamente en tiempo real sobre incidentes críticos, junto con las recomendaciones para mitigar el ataque.

### 6. Revisión de la documentación y pruebas continuas

Es esencial que la documentación continúe evolucionando con cada mejora y cambio en el sistema. Algunas áreas clave incluyen:

- **Documentar las nuevas reglas de detección**: Al agregar más cobertura ATT&CK, asegurarse de documentar adecuadamente todas las reglas y técnicas que se han implementado.
    
- **Pruebas continuas**: Hacer pruebas regulares de todas las técnicas para asegurarse de que las detecciones se mantienen efectivas y que no se introducen nuevos falsos positivos.

---

**Conclusión**: El trabajo futuro se enfoca en una serie de mejoras que buscan consolidar un sistema de detección más robusto, preciso y capaz de automatizar respuestas ante incidentes. Es importante que el laboratorio continúe evolucionando con el tiempo para hacer frente a nuevas amenazas y mejorar la efectividad de las herramientas implementadas.
