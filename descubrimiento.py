# =============================================================================
# AuditX - descubrimiento.py
# =============================================================================
# Fase 1: Descubrimiento de hosts y escaneo de puertos mediante nmap.
# =============================================================================

import subprocess
import re
from configuracion import (Colores, TIMEOUT_NMAP, PUERTOS_WEB,
                           FLAGS_NMAP_RAPIDO, FLAGS_NMAP_SIGILOSO, FLAGS_NMAP_VERSIONES)


def ejecutar_descubrimiento(objetivo: str, sigiloso: bool = False) -> dict:
    """
    Ejecuta el descubrimiento de puertos y servicios sobre el objetivo.

    Args:
        objetivo : IP o hostname del objetivo.
        sigiloso : Si True, usa escaneo SYN sigiloso (-sS).

    Returns:
        Diccionario con los resultados estructurados del escaneo.
    """
    print(f"\n[*] FASE 1 — Descubrimiento de puertos y servicios")
    print(f"    Objetivo : {objetivo}")

    resultados = {
        "objetivo"         : objetivo,
        "puertos"          : [],
        "sistema_operativo": "Desconocido",
        "salida_raw"       : "",
        "errores"          : []
    }

    print(f"    [~] Escaneando todos los puertos TCP...")
    puertos_abiertos = _escanear_todos_puertos(objetivo, sigiloso, resultados)

    if not puertos_abiertos:
        print(f"    {Colores.ERROR}[!] No se encontraron puertos abiertos.{Colores.FIN}")
        return resultados

    print(f"    [+] Puertos abiertos: {', '.join(map(str, puertos_abiertos))}")
    print(f"    [~] Analizando versiones y servicios...")
    _escanear_versiones_servicios(objetivo, puertos_abiertos, resultados)

    _imprimir_resumen_descubrimiento(resultados)
    return resultados


def _escanear_todos_puertos(objetivo: str, sigiloso: bool, resultados: dict) -> list:
    """Escaneo TCP de todos los puertos para identificar cuáles están abiertos."""
    flags = FLAGS_NMAP_SIGILOSO if sigiloso else FLAGS_NMAP_RAPIDO
    cmd   = ["nmap"] + flags.split() + [objetivo]

    try:
        salida = _ejecutar_comando(cmd, TIMEOUT_NMAP)
        resultados["salida_raw"] += salida
        return _parsear_puertos_abiertos(salida)
    except Exception as e:
        resultados["errores"].append(f"Error en escaneo de puertos: {str(e)}")
        return []


def _escanear_versiones_servicios(objetivo: str, puertos: list, resultados: dict):
    """Detección de versiones, scripts por defecto y sistema operativo."""
    puertos_str = ",".join(map(str, puertos))
    cmd = ["nmap"] + FLAGS_NMAP_VERSIONES.split() + ["-p", puertos_str, objetivo]

    try:
        salida = _ejecutar_comando(cmd, TIMEOUT_NMAP)
        resultados["salida_raw"] += "\n" + salida
        _parsear_info_servicios(salida, resultados)
    except Exception as e:
        resultados["errores"].append(f"Error en detección de versiones: {str(e)}")


def _parsear_puertos_abiertos(salida_nmap: str) -> list:
    """Extrae los números de puerto abiertos de la salida de nmap."""
    patron = r"(\d+)/tcp\s+open"
    return [int(p) for p in re.findall(patron, salida_nmap)]


def _parsear_info_servicios(salida_nmap: str, resultados: dict):
    """Parsea la salida detallada de nmap y rellena el diccionario de resultados."""
    coincidencia_so = re.search(r"OS details:\s*(.+)", salida_nmap)
    if coincidencia_so:
        resultados["sistema_operativo"] = coincidencia_so.group(1).strip()

    patron_puerto = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
    )
    for coincidencia in patron_puerto.finditer(salida_nmap):
        info_puerto = {
            "puerto"    : int(coincidencia.group(1)),
            "protocolo" : coincidencia.group(2),
            "estado"    : coincidencia.group(3),
            "servicio"  : coincidencia.group(4),
            "version"   : coincidencia.group(5).strip(),
            "es_web"    : int(coincidencia.group(1)) in PUERTOS_WEB
        }
        resultados["puertos"].append(info_puerto)

    hay_puertos_web = any(p["es_web"] for p in resultados["puertos"])
    if hay_puertos_web:
        _extraer_metadatos_http(salida_nmap, resultados)


def _extraer_metadatos_http(salida_nmap: str, resultados: dict):
    """Extrae información extra de scripts HTTP de nmap."""
    metadatos = {}

    m_titulo = re.search(r"http-title:\s*(.+)", salida_nmap)
    if m_titulo:
        metadatos["titulo"] = m_titulo.group(1).strip()

    m_generador = re.search(r"http-generator:\s*(.+)", salida_nmap)
    if m_generador:
        metadatos["generador"] = m_generador.group(1).strip()

    m_servidor = re.search(r"http-server-header:\s*(.+)", salida_nmap)
    if m_servidor:
        metadatos["servidor"] = m_servidor.group(1).strip()

    if metadatos:
        resultados["metadatos_http"] = metadatos


def _imprimir_resumen_descubrimiento(resultados: dict):
    """Imprime un resumen legible de los resultados del descubrimiento."""
    print(f"\n    [+] Resumen del descubrimiento:")
    print(f"        SO detectado : {resultados.get('sistema_operativo', 'Desconocido')}")

    for p in resultados["puertos"]:
        etiqueta_web = "[WEB] " if p["es_web"] else ""
        print(f"        {etiqueta_web}{p['puerto']}/{p['protocolo']} — {p['servicio']} {p['version']}")

    if resultados.get("metadatos_http"):
        meta = resultados["metadatos_http"]
        print(f"\n        Titulo web : {meta.get('titulo', 'N/A')}")
        print(f"        Generador  : {meta.get('generador', 'N/A')}")
        print(f"        Servidor   : {meta.get('servidor', 'N/A')}")

    for error in resultados["errores"]:
        print(f"        {Colores.ERROR}[!] {error}{Colores.FIN}")


def _ejecutar_comando(cmd: list, timeout: int) -> str:
    """Ejecuta un comando de sistema y devuelve su salida como string."""
    proceso = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return proceso.stdout + proceso.stderr
