# =============================================================================
# AuditX - fingerprinting/base.py
# =============================================================================
# Utilidades compartidas por todos los módulos de fingerprinting:
# ejecución de comandos, banner grabbing por socket y registro de tecnologías.
# =============================================================================

import subprocess
import socket
from configuracion import Colores, TIMEOUT_SOCKET, TIMEOUT_COMANDO


def banner_socket(host: str, puerto: int, probe: str = None) -> str:
    """Conecta por socket, envía un probe opcional y devuelve el banner recibido."""
    try:
        with socket.create_connection((host, puerto), timeout=TIMEOUT_SOCKET) as s:
            if probe:
                s.sendall(probe.encode())
            datos = s.recv(1024)
            return datos.decode(errors="ignore")
    except Exception:
        return ""


def ejecutar_nmap_script(host: str, puerto: int, scripts: str) -> str:
    """Ejecuta nmap con uno o varios scripts y devuelve la salida."""
    cmd = ["nmap", "-n", "-Pn", "--script", scripts, "-p", str(puerto), host]
    try:
        return ejecutar_comando(cmd)
    except Exception:
        return ""


def ejecutar_comando(cmd: list) -> str:
    """Ejecuta un comando (lista de args) y devuelve stdout + stderr."""
    proceso = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_COMANDO
    )
    return proceso.stdout + proceso.stderr


def agregar_tecnologia(tech: str, resultados: dict, info: dict = None):
    """Añade una tecnología a la lista global y, opcionalmente, a la info del servicio."""
    if tech and tech not in resultados["tecnologias"]:
        resultados["tecnologias"].append(tech)
    if info is not None and tech:
        info.setdefault("tecnologias", [])
        if tech not in info["tecnologias"]:
            info["tecnologias"].append(tech)


def fingerprint_banner_generico(objetivo: str, puerto: int, tipo: str, resultados: dict):
    """Banner grabbing por socket para servicios sin handler específico."""
    info = {"banner": None}

    probe = "EHLO auditx\r\n" if tipo == "smtp" else None
    banner = banner_socket(objetivo, puerto, probe=probe)

    if banner:
        resultados["salida_raw"] += banner
        info["banner"] = banner.strip()
        primera_linea = banner.splitlines()[0][:60] if banner.splitlines() else ""
        agregar_tecnologia(f"{tipo.upper()} {primera_linea}", resultados)

    resultados["servicios"][f"{tipo}:{puerto}"] = info
