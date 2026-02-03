# sIgnoto - Network Scanner & Analyzer

Este repositorio contiene scripts en Bash diseñados para el análisis y escaneo de redes locales. Estas herramientas facilitan la identificación de hosts, detección de sistemas operativos y enumeración de servicios.

## Scripts Disponibles

### 1. `sIgnoto.sh`
Es la versión original del escáner. Sus principales funciones son:
- Identificación del segmento de red local.
- Búsqueda de equipos activos mediante `arp-scan`.
- Estimación del Sistema Operativo basado en el TTL (Time To Live) de la respuesta ping.
- Escaneo de puertos abiertos y servicios.
- Generación de archivos de texto con los resultados.

### 2. `sIgnotoB.sh` (Versión Mejorada)
Una evolución moderna del script original que incluye mejoras significativas:
- **Interfaz Visual Mejorada**: Uso de colores ANSI, barras de progreso y tablas formateadas para una mejor legibilidad.
- **Detección de SO Avanzada**: Lógica ampliada para identificar más sistemas operativos basados en TTL.
- **Escaneo Nmap Optimizado**: Ejecuta un escaneo más completo (`-sS -sV -sC -Pn`) para obtener detalles precisos de versiones y scripts.
- **Organización de Resultados**: Crea automáticamente carpetas por IP escaneada (`scans/<IP>/`) para mantener ordenados los reportes.
- **Reportes Detallados**: Genera un resumen final con fecha, hora, detalles del host y servicios encontrados.

## Requisitos Previos

Para ejecutar estos scripts correctamente, asegúrate de tener instaladas las siguientes herramientas en tu sistema Linux:

```bash
sudo apt update
sudo apt install nmap arp-scan
```

## Uso

Dale permisos de ejecución al script que desees utilizar:

```bash
chmod +x sIgnotoB.sh
```

Ejecuta el script con privilegios de superusuario (necesario para `arp-scan` y escaneos SYN de `nmap`):

```bash
sudo ./sIgnotoB.sh
```

## Notas
- Los scripts están diseñados con fines educativos y de administración de redes. Úsalos responsablemente en redes propias o autorizadas.
