# Configuración de pfSense en el laboratorio SOC

## 1. Versión y entorno

- **Producto**: pfSense CE
- **Versión**: 2.8.1-RELEASE (amd64)
- **Plataforma**: Máquina virtual VMware
- **Hostname**: `pfsense.home.ara` (según dashboard)

---

## 2. Interfaces configuradas

| Interfaz | Nombre | IP / Máscara       | Tipo      | Uso principal                          |
|----------|--------|--------------------|-----------|----------------------------------------|
| em0      | WAN    | 192.168.184.128/24 | WAN       | Salida hacia red externa / VMware      |
| em1      | LAN    | 192.168.10.1/24    | LAN       | Red de servidores (incluye Wazuh)      |
| em2      | OPT1   | 192.168.20.1/24    | OPT (LAN) | Red de endpoints (Windows 11)          |
| em3      | OPT2   | 192.168.30.1/24    | OPT (LAN) | Segmento reservado                     |
| em4      | OPT3   | 192.168.40.1/24    | OPT (LAN) | Red de atacante (Kali)                 |

---

## 3. Reglas de firewall

### 3.1 WAN

Reglas por defecto para endurecer la interfaz de entrada:

| # | Acción | Proto | Origen             | Destino | Puertos | Descripción              |
|---|--------|-------|--------------------|---------|---------|--------------------------|
| 1 | Block  | *     | RFC 1918 networks  | *       | *       | Block private networks   |
| 2 | Block  | *     | Reserved (bogons)  | *       | *       | Block bogon networks     |

No se permite tráfico entrante hacia las redes internas desde la WAN.

---

### 3.2 LAN (192.168.10.0/24)

Reglas para administración y acceso desde la red LAN (donde está Wazuh):

| # | Acción | Proto     | Origen        | Puertos origen | Destino          | Puertos destino | Descripción                                       |
|---|--------|-----------|--------------|----------------|------------------|-----------------|---------------------------------------------------|
| 1 | Pass   | TCP       | *            | *              | LAN Address      | 443, 80         | Anti-lockout rule (acceso WebGUI pfSense)         |
| 2 | Pass   | UDP       | WAZUH_SERVER | *              | This Firewall    | 53 (DNS)        | DNS para el servidor Wazuh                        |
| 3 | Pass   | UDP       | LAN subnets  | *              | This Firewall    | 53 (DNS)        | DNS para otros hosts LAN                          |
| 4 | Pass   | ICMP      | LAN subnets  | *              | This Firewall    | any             | Permitir ping a pfSense desde LAN                 |
| 5 | Pass   | TCP       | LAN subnets  | *              | 192.168.10.10    | *               | Acceso desde LAN a Wazuh server                   |
| 6 | Pass   | TCP       | LAN subnets  | *              | OPT1 address     | 53 (DNS)        | DNS hacia OPT1 (si actúa como forwarder)          |
| 7 | Pass   | IPv6/TCP* | LAN subnets  | *              | any              | *               | Default allow LAN IPv6 to any (por defecto, opc.) |

> *Los números exactos pueden variar, pero la lógica es: mantener administración de pfSense y permitir que la red LAN hable con Wazuh y otros segmentos internos de forma controlada.*

---

### 3.3 OPT1 – Red de endpoints (192.168.20.0/24)

OPT1 es donde se encuentra el Windows 11 que actúa como endpoint monitorizado y desde donde se lanza el tráfico hacia Wazuh y pfSense.

| # | Acción | Proto | Origen         | Destino        | Puerto destino           | Descripción                                                |
|---|--------|-------|----------------|----------------|--------------------------|------------------------------------------------------------|
| 1 | Pass   | TCP   | OPT1 subnets   | 192.168.10.10  | WAZUH_PORTS              | Acceso a Dashboard/API de Wazuh (alias de puertos)         |
| 2 | Pass   | ICMP  | OPT1 subnets   | This Firewall  | *                        | Permitir ping a pfSense desde OPT1                         |
| 3 | Pass   | UDP   | OPT1 subnets   | This Firewall  | 53 (DNS)                 | DNS desde OPT1 hacia pfSense                               |
| 4 | Pass   | TCP   | OPT1 subnets   | 192.168.10.10  | 1514                     | Envío de logs Wazuh agent → manager                        |
| 5 | Pass   | TCP   | OPT1 subnets   | 192.168.10.10  | 1515                     | Registro de agentes / canal adicional de Wazuh             |
| 6 | Pass   | IPv4  | OPT1 subnets   | any            | *                        | Regla “allow any” (laboratorio) para tráfico adicional     |

> En un entorno productivo, la regla 6 se iría endureciendo con reglas más específicas; en el laboratorio facilita las pruebas de conectividad.

---

### 3.4 OPT3 – Red atacante (192.168.40.0/24)

Segmento reservado para la máquina Kali Linux. Por ahora está fuertemente restringido:

| # | Acción | Proto | Origen       | Destino       | Puerto | Descripción                          |
|---|--------|-------|--------------|--------------|--------|--------------------------------------|
| 1 | Pass   | ICMP  | OPT3 subnets | This Firewall| *      | Permitir ping hacia pfSense (solo ICMP) |

Actualmente no hay reglas que permitan tráfico desde OPT3 hacia LAN u OPT1. Esto permite:

- Hacer pruebas de **escaneo y reconocimiento** contra pfSense.
- Mantener a Wazuh y al endpoint aislados, hasta que en Fase 2 se diseñen ataques controlados específicos (por ejemplo simulaciones desde Kali hacia el Windows 11).

---

## 4. Aliases relevantes

En las reglas se usan algunos *aliases* para simplificar:

- **`WAZUH_SERVER`**: alias que apunta a `192.168.10.10`.
- **`WAZUH_PORTS`**: grupo de puertos TCP usados por Wazuh (dashboard, API, etc.).
- **`LAN subnets`, `OPT1 subnets`, `OPT3 subnets`**: redes completas de cada interfaz.

El uso de aliases hace más fácil modificar puertos/IPS de Wazuh sin tocar todas las reglas.

---

## 5. Endurecimiento básico aplicado

- En **WAN** se bloquean redes privadas RFC1918 y bogons.
- El acceso al WebGUI de pfSense está protegido por la *Anti-lockout rule* y restringido a IPs internas.
- Las redes se encuentran **segmentadas**:
  - `LAN` para servidores (Wazuh).
  - `OPT1` para endpoints monitorizados.
  - `OPT3` para atacante (Kali).
- Desde la perspectiva del laboratorio SOC:
  - El tráfico necesario para la telemetría (Wazuh agent → manager) está explícitamente permitido.
  - El resto del tráfico se controla por interfaz, imitando una red corporativa segmentada.


> [!**NOTA IMPORTANTE**]: Lo desarrollado en todo este apartado pertenece a la configuración base de pfsense. En fases posteriores, documentadas respectivamente en el apartado [[docs]], se añadieron reglas a pfsense para acoplar a los objetivos desplegados en cada escenario.
