#!/bin/bash
# ╔════════════════════════════════════════════════════════════════════════════════╗
# ║                        Escáner de Red con Nmap                                 ║
# ║ Autor: Moisés Beltrán D.                                                       ║
# ║ Descripción:                                                                   ║
# ║ - Detecta IPs activas en la red local                                          ║
# ║ - Estima sistema operativo según TTL                                           ║
# ║ - Escanea puertos abiertos y servicios con Nmap                                ║
# ║ - Genera reporte moderno con barras de progreso                                ║
# ╚════════════════════════════════════════════════════════════════════════════════╝

# ───────────────────────────────
# Colores ANSI para formato
# ───────────────────────────────
BLUE='\e[1;34m'
GREEN='\e[0;32m'
YELLOW='\e[0;33m'
RED='\e[0;31m'
RESET='\e[0m'

# ───────────────────────────────
# Variables globales
# ───────────────────────────────
hostEncontrado=()
puertoEncontrado=()
servicioEncontrado=()
ancho=70

# ───────────────────────────────
# Funciones visuales
# ───────────────────────────────
barra_progreso() {
    local progreso=$1
    local total=$2
    local ancho_barra=50
    local porcentaje=$((100 * progreso / total))
    local completados=$((ancho_barra * progreso / total))
    local restantes=$((ancho_barra - completados))

    printf "\r["
    for ((i = 0; i < completados; i++)); do printf "#"; done
    for ((i = 0; i < restantes; i++)); do printf "."; done
    printf "] %3d%%" "$porcentaje"
    [[ $progreso -eq $total ]] && echo ""
}

imprimir_titulo() {
    local titulo="$1"
    local padding=$(( (ancho - ${#titulo}) / 2 ))
    local borde=$(printf '═%.0s' $(seq 1 $ancho))

    echo -e "${BLUE}╔$borde╗${RESET}"
    printf "${BLUE}║%*s${GREEN}%s${BLUE}%*s║${RESET}\n" \
        "$padding" "" "$titulo" "$((ancho - padding - ${#titulo}))" ""
    echo -e "${BLUE}╚$borde╝${RESET}"
}

imprimir_subtitulo() {
    local texto="$1"
    local borde=$(printf '%*s\n' "$ancho" '' | tr ' ' '-')
    echo -e "${YELLOW}$borde${RESET}"
    printf "${YELLOW}-- %-*s --${RESET}\n" "$((ancho - 6))" "$texto"
    echo -e "${YELLOW}$borde${RESET}"
}

# ───────────────────────────────
# Funciones principales
# ───────────────────────────────
verIPsegmento() {
    miIP=$(echo "$ipSegmento" | awk '{print $8}')
    segmento=$(echo "$miIP" | cut -d '.' -f1-3)
    echo -e "${YELLOW}IP local:       ${RESET}$miIP"
    echo -e "${YELLOW}Segmento /24:   ${RESET}$segmento.x"
}

crearArchivoHost() {
    imprimir_subtitulo "Escaneando red para encontrar hosts activos..."
    sudo arp-scan -l --format='${ip}' | grep "^$segmento" | sort > "00_host.txt"
    echo -e "${GREEN}✔ Escaneo de red completo${RESET}"
}

leerArchivoHost() {
    while IFS= read -r linea; do
        hostEncontrado+=("$linea")
    done < "00_host.txt"
}

verIPencontrada() {
    imprimir_subtitulo "IPs encontradas en la red"
    for i in "${!hostEncontrado[@]}"; do
        printf "[%02d] - %s\n" "$i" "${hostEncontrado[$i]}"
    done
}

leerOpcion() {
    read -p "Seleccione ID de IP objetivo: " idMenu
    validarOpcion

    ipSeleccionada="${hostEncontrado[$idMenu]}"
    carpeta="scans/$ipSeleccionada"
    mkdir -p "$carpeta"
}

validarOpcion() {
    while ! [[ "$idMenu" =~ ^[0-9]+$ ]] || [ "$idMenu" -lt 0 ] || [ "$idMenu" -ge "${#hostEncontrado[@]}" ]; do
        echo -e "${RED}Opción inválida. Intente nuevamente.${RESET}"
        sleep 1
        leerOpcion
    done
}

buscaTTL() {
    barra_progreso 1 3
    ipTTL=$(ping -c 1 "${hostEncontrado[$idMenu]}" | grep -oE "ttl=[0-9]{1,3}" | cut -d= -f2)
    barra_progreso 3 3
}

ttl_to_os() {
    case "$1" in
        30) echo "Cisco IOS / embebido";;
        32) echo "Windows IoT / cámaras IP";;
        60) echo "Router doméstico";;
        64) echo "Linux / Android / macOS";;
        65) echo "OpenBSD";;
        128) echo "Windows (moderno)";;
        254) echo "AIX / Solaris";;
        255) echo "BSD / Cisco";;
        *)
            if [ "$1" -lt 64 ]; then echo "Unix embebido";
            elif [ "$1" -lt 128 ]; then echo "Linux probable";
            elif [ "$1" -lt 200 ]; then echo "Windows probable";
            else echo "Dispositivo de red";
            fi
        ;;
    esac
}

verSOsegunTTL() {
    imprimir_subtitulo "Detección del Sistema Operativo (por TTL)"
    buscaTTL
    if [ "$ipTTL" ]; then
        posibleSistema=$(ttl_to_os "$ipTTL")
        echo -e "IP: ${hostEncontrado[$idMenu]}  | TTL: $ipTTL  | SO: $posibleSistema"
    else
        echo -e "${RED}No se pudo obtener TTL.${RESET}"
    fi
}

scan_nmap_completo() {
    imprimir_subtitulo "Escaneo de Puertos y Servicios con Nmap"
    barra_progreso 1 5
    sudo nmap -sS -sV -sC -Pn -T4 -p- --min-rate=1000 --max-retries=2 \
        "${hostEncontrado[$idMenu]}" -oN "$carpeta/02_servicio_${hostEncontrado[$idMenu]}.txt"
    barra_progreso 5 5

    grep "open" "$carpeta/02_servicio_${hostEncontrado[$idMenu]}.txt" | awk '{print $1}' > "$carpeta/01_puerto_${hostEncontrado[$idMenu]}.txt"
}

leerArchivoPuerto() {
    while IFS= read -r linea; do
        puertoEncontrado+=("$linea")
    done < "$carpeta/01_puerto_${hostEncontrado[$idMenu]}.txt"
}

verPuerto() {
    imprimir_subtitulo "Puertos abiertos encontrados"
    printf "%s\n" "${puertoEncontrado[@]}"
}

leerArchivoServicio() {
    while IFS= read -r linea; do
        servicioEncontrado+=("$linea")
    done < "$carpeta/02_servicio_${hostEncontrado[$idMenu]}.txt"
}

verServicioEncontrado() {
    imprimir_subtitulo "Servicios identificados"
    printf "%-12s | %-18s | %-s\n" "Puerto" "Servicio" "Versión"
    printf -- "%-12s-+-%-18s-+-%s\n" "------------" "------------------" "-------------------------------"
    for linea in "${servicioEncontrado[@]}"; do
        sPuerto=$(echo "$linea" | awk '{print $1}')
        sServicio=$(echo "$linea" | awk '{print $3}')
        sVersion=$(echo "$linea" | cut -d ' ' -f4-)
        printf "%-12s | %-18s | %-s\n" "$sPuerto" "$sServicio" "$sVersion"
    done
}

generarArchivoReport() {
    read -p "¿Desea generar reporte (S/N)? " crearResumen
    if [[ "$crearResumen" =~ ^[Ss]$ ]]; then
        archivo="$carpeta/03_reporte_${hostEncontrado[$idMenu]}.txt"
        timestamp=$(date "+%Y-%m-%d %H:%M:%S")

        {
            echo "========================= REPORTE DE ESCANEO ========================="
            echo "Fecha/Hora       : $timestamp"
            echo "IP Escaneada     : ${hostEncontrado[$idMenu]}"
            echo "TTL              : ${ipTTL:-No detectado}"
            echo "Sistema Operativo: $(ttl_to_os "$ipTTL")"
            echo
            echo "-- PUERTOS ABIERTOS --"
            printf "%s\n" "${puertoEncontrado[@]}"
            echo
            echo "-- SERVICIOS DETECTADOS --"
            for linea in "${servicioEncontrado[@]}"; do
                echo "$linea"
            done
            echo "====================================================================="
        } > "$archivo"

        echo -e "${GREEN}✔ Reporte guardado en: ${RESET}$(realpath "$archivo")"
    fi
}

# ───────────────────────────────
# EJECUCIÓN PRINCIPAL
# ───────────────────────────────
clear
imprimir_titulo "Red Scanner – Escáner de Red con Nmap + TTL"
ipSegmento=$(sudo arp-scan -l -M 1 | grep "Interface")
verIPsegmento
crearArchivoHost
leerArchivoHost
verIPencontrada
leerOpcion
verSOsegunTTL
scan_nmap_completo
leerArchivoPuerto
verPuerto
leerArchivoServicio
verServicioEncontrado
generarArchivoReport
