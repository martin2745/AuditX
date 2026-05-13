# =============================================================================
# AuditX - fingerprinting/smb.py
# =============================================================================
# Fingerprinting del servicio SMB: detección de OS, nivel de cifrado y
# estado de message signing mediante nmap scripts.
# =============================================================================

import re
from configuracion import Colores
from .base import ejecutar_nmap_script, agregar_tecnologia


def fingerprint_smb(objetivo: str, puerto: int, resultados: dict):
    """Información de SMB mediante nmap scripts."""
    info = {"os": None, "firmar": None}

    salida = ejecutar_nmap_script(objetivo, puerto, "smb-security-mode,smb-os-discovery")
    if salida:
        resultados["salida_raw"] += salida
        info["nmap_info"] = salida.strip()
        agregar_tecnologia(f"SMB (puerto {puerto})", resultados)

        m_os = re.search(r"OS:\s+(.+)", salida)
        if m_os:
            info["os"] = m_os.group(1).strip()

        m_sig = re.search(r"message_signing:\s+(\w+)", salida)
        if m_sig:
            info["firmar"] = m_sig.group(1)
            if m_sig.group(1) == "disabled":
                print(f"        {Colores.ADVERTENCIA}[!] SMB message signing deshabilitado{Colores.FIN}")

    resultados["servicios"][f"smb:{puerto}"] = info
