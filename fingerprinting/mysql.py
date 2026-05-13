# =============================================================================
# AuditX - fingerprinting/mysql.py
# =============================================================================
# Fingerprinting del servicio MySQL: extracción de versión desde el paquete
# de saludo del protocolo y complemento con nmap mysql-info.
# =============================================================================

import re
import socket
from configuracion import TIMEOUT_SOCKET
from .base import ejecutar_nmap_script, agregar_tecnologia


def fingerprint_mysql(objetivo: str, puerto: int, resultados: dict):
    """Extrae versión MySQL del paquete de saludo del protocolo + nmap."""
    info = {"banner": None, "version": None}

    try:
        with socket.create_connection((objetivo, puerto), timeout=TIMEOUT_SOCKET) as s:
            datos = s.recv(256)
            resultados["salida_raw"] += repr(datos)
            # El saludo MySQL: 4 bytes cabecera + 1 byte versión protocolo + versión NUL-terminada
            if len(datos) > 5:
                version_raw = datos[5:].split(b"\x00")[0].decode(errors="ignore")
                if re.match(r"[\d.]+", version_raw):
                    info["version"] = version_raw
                    info["banner"] = f"MySQL {version_raw}"
                    agregar_tecnologia(f"MySQL {version_raw}", resultados)
    except Exception as e:
        resultados["errores"].append(f"Error leyendo banner MySQL en puerto {puerto}: {str(e)}")

    salida_nmap = ejecutar_nmap_script(objetivo, puerto, "mysql-info")
    if salida_nmap:
        resultados["salida_raw"] += salida_nmap
        if not info["version"]:
            m = re.search(r"Version:\s+([\d.]+)", salida_nmap)
            if m:
                info["version"] = m.group(1)
                agregar_tecnologia(f"MySQL {m.group(1)}", resultados)
        info["nmap_info"] = salida_nmap.strip()

    resultados["servicios"][f"mysql:{puerto}"] = info
