# =============================================================================
# AuditX - escaneo_red.py
# =============================================================================
# Fase 0: Descubrimiento de hosts activos en la red mediante ping sweep.
# =============================================================================

import subprocess
import re
from configuracion import Colores, TIMEOUT_NMAP


def ejecutar_escaneo_red(red: str) -> list:
    """
    Realiza un ping sweep sobre la red para descubrir hosts activos.

    Args:
        red : Rango de red en formato CIDR (ej: 192.168.100.0/24)

    Returns:
        Lista de dicts con 'ip', 'nombre_host', 'mac', 'fabricante'
    """
    print(f"\n[*] Escaneando red: {red}")
    print(f"    Esto puede tardar unos segundos...\n")

    cmd = ["nmap", "-sn", red]

    try:
        proceso = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NMAP
        )
        return _parsear_hosts(proceso.stdout)

    except FileNotFoundError:
        print(f"{Colores.ERROR}[!] nmap no encontrado.{Colores.FIN}")
        return []
    except subprocess.TimeoutExpired:
        print(f"{Colores.ERROR}[!] Timeout escaneando la red.{Colores.FIN}")
        return []
    except Exception as e:
        print(f"{Colores.ERROR}[!] Error en el escaneo de red: {e}{Colores.FIN}")
        return []


def _parsear_hosts(salida: str) -> list:
    """Parsea la salida de nmap -sn y extrae IPs, hostnames y MACs."""
    hosts  = []
    actual = {}

    for linea in salida.splitlines():
        coincidencia_host = re.search(r"Nmap scan report for (.+)", linea)
        if coincidencia_host:
            if actual:
                hosts.append(actual)
            info = coincidencia_host.group(1).strip()
            coincidencia_ip = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", info)
            if coincidencia_ip:
                ip          = coincidencia_ip.group(1)
                nombre_host = info.split("(")[0].strip()
            else:
                ip          = info
                nombre_host = ""
            actual = {"ip": ip, "nombre_host": nombre_host, "mac": "", "fabricante": ""}
            continue

        coincidencia_mac = re.search(r"MAC Address: ([0-9A-F:]+)(?:\s+\((.+)\))?", linea)
        if coincidencia_mac and actual:
            actual["mac"]        = coincidencia_mac.group(1)
            actual["fabricante"] = coincidencia_mac.group(2) or ""

    if actual:
        hosts.append(actual)

    return hosts


def imprimir_tabla_hosts(hosts: list):
    """Imprime la tabla de hosts descubiertos con índice para selección."""
    print(f"\n[+] Hosts activos descubiertos: {len(hosts)}\n")
    print(f"    {'#':<4} {'IP':<18} {'Nombre host':<25} {'MAC':<20} Fabricante")
    print(f"    {'-'*4} {'-'*18} {'-'*25} {'-'*20} {'-'*15}")

    for i, host in enumerate(hosts, 1):
        nombre_host = host["nombre_host"] or "-"
        mac         = host["mac"]         or "-"
        fabricante  = host["fabricante"]  or "-"
        print(f"    {i:<4} {host['ip']:<18} {nombre_host:<25} {mac:<20} {fabricante}")
    print()


def seleccionar_objetivo(hosts: list) -> str:
    """
    Muestra la tabla de hosts y pide al usuario que seleccione uno.

    Returns:
        IP del host seleccionado, o "" si el usuario cancela.
    """
    imprimir_tabla_hosts(hosts)

    while True:
        try:
            entrada = input(
                f"  Selecciona el numero del host a auditar (1-{len(hosts)}) o 'q' para salir: "
            ).strip().lower()
        except KeyboardInterrupt:
            return ""

        if entrada in ("q", "salir", "exit"):
            return ""

        if entrada.isdigit():
            indice = int(entrada)
            if 1 <= indice <= len(hosts):
                return hosts[indice - 1]["ip"]

        print(f"    {Colores.ERROR}[!] Opcion no valida. Introduce un numero entre 1 y {len(hosts)}.{Colores.FIN}")


def preguntar_continuar(hosts: list) -> str:
    """
    Pregunta si se quiere auditar otro host tras finalizar una auditoría.

    Returns:
        IP del siguiente host, o "" para terminar.
    """
    try:
        respuesta = input(f"\n  ¿Auditar otro host? [s/N]: ").strip().lower()
    except KeyboardInterrupt:
        return ""

    if respuesta in ("s", "si", "sí", "yes", "y"):
        return seleccionar_objetivo(hosts)

    return ""
