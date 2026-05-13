# =============================================================================
# AuditX - fingerprinting/ssh.py
# =============================================================================
# Fingerprinting del servicio SSH: banner grabbing y enumeración de algoritmos.
# =============================================================================

import re
from .base import banner_socket, ejecutar_nmap_script, agregar_tecnologia


def fingerprint_ssh(objetivo: str, puerto: int, resultados: dict):
    """Banner grabbing SSH + enumeración de algoritmos con nmap."""
    info = {"banner": None, "version": None, "algoritmos": []}

    banner = banner_socket(objetivo, puerto)
    if banner:
        resultados["salida_raw"] += banner
        info["banner"] = banner.strip()
        m = re.search(r"SSH-[\d.]+-([^\r\n]+)", banner)
        if m:
            version = m.group(1).strip()
            info["version"] = version
            agregar_tecnologia(f"SSH {version}", resultados)

    salida_nmap = ejecutar_nmap_script(objetivo, puerto, "ssh2-enum-algos")
    if salida_nmap:
        resultados["salida_raw"] += salida_nmap
        info["algoritmos"] = _parsear_algoritmos(salida_nmap)

    resultados["servicios"][f"ssh:{puerto}"] = info


def _parsear_algoritmos(salida: str) -> list:
    algoritmos = []
    for linea in salida.splitlines():
        linea = linea.strip()
        if linea.startswith("|") and ":" not in linea:
            alg = linea.lstrip("|_ ").strip()
            if alg:
                algoritmos.append(alg)
    return algoritmos
