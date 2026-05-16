# =============================================================================
# AuditX - busqueda_vulnerabilidades.py
# =============================================================================
# Fase 4: Búsqueda de vulnerabilidades conocidas (CVEs) mediante searchsploit.
# Clasifica los hallazgos según el estándar OWASP Top 10 2021.
# =============================================================================

import subprocess
import re
import json
from configuracion import (Colores, TIMEOUT_COMANDO, MAX_TERMINOS_SEARCHSPLOIT,
                           MAX_PALABRAS_VERSION, SEVERIDAD_DEFECTO,
                           OWASP_CATEGORIA_DEFECTO, MAPEO_OWASP,
                           PALABRAS_CLAVE_SEVERIDAD)


def ejecutar_busqueda_vulnerabilidades(resultados_descubrimiento: dict, resultados_fingerprinting: dict) -> dict:
    """
    Busca vulnerabilidades conocidas para los servicios y tecnologías detectadas.

    Args:
        resultados_descubrimiento  : Resultados del módulo descubrimiento (fase 1).
        resultados_fingerprinting  : Resultados del módulo fingerprinting (fase 2).

    Returns:
        Diccionario con CVEs, exploits y clasificación OWASP.
    """
    print(f"\n[*] FASE 3 — Búsqueda de vulnerabilidades conocidas")

    resultados = {
        "vulnerabilidades" : [],
        "hallazgos_owasp"  : {},
        "cantidad_criticas": 0,
        "cantidad_altas"   : 0,
        "cantidad_medias"  : 0,
        "cantidad_bajas"   : 0,
        "salida_raw"       : "",
        "errores"          : []
    }

    terminos_busqueda = _construir_terminos_busqueda(resultados_descubrimiento, resultados_fingerprinting)

    if not terminos_busqueda:
        print(f"    [!] No hay servicios o tecnologias identificadas para buscar.")
        return resultados

    for termino in terminos_busqueda:
        print(f"    [~] Buscando exploits para: {termino}")
        _buscar_exploitdb(termino, resultados)

    _contar_por_severidad(resultados)
    _construir_resumen_owasp(resultados)
    _imprimir_resumen_vulnerabilidades(resultados)
    return resultados


def _construir_terminos_busqueda(descubrimiento: dict, fingerprinting: dict) -> list:
    """
    Construye los términos de búsqueda combinando:
    - Servicios y versiones detectados por nmap (fase 1)
    - Tecnologías web detectadas por fingerprinting (fase 2)
    """
    terminos = []

    # --- Fuente 1: servicios de red detectados por nmap ---
    for puerto in descubrimiento.get("puertos", []):
        servicio = puerto.get("servicio", "")
        version  = puerto.get("version", "")
        if servicio and version:
            # Cogemos solo las dos primeras palabras de la versión para no
            # construir un término demasiado largo que no devuelva resultados
            partes_version = version.split()[:MAX_PALABRAS_VERSION]
            termino = f"{servicio} {' '.join(partes_version)}".strip()
            if termino not in terminos:
                terminos.append(termino)

    # --- Fuente 2: tecnologías web detectadas por fingerprinting ---
    if fingerprinting.get("cms") and fingerprinting.get("version_cms"):
        termino_cms = f"{fingerprinting['cms']} {fingerprinting['version_cms']}"
        if termino_cms not in terminos:
            terminos.append(termino_cms)

    if fingerprinting.get("servidor_web"):
        servidor = fingerprinting["servidor_web"]
        partes   = re.split(r"[/\s]", servidor)
        if len(partes) >= 2:
            termino_srv = f"{partes[0]} {partes[1]}"
            if termino_srv not in terminos:
                terminos.append(termino_srv)

    for tech in fingerprinting.get("tecnologias", []):
        if re.search(r"\d", tech) and tech not in terminos:
            terminos.append(tech)

    return terminos[:MAX_TERMINOS_SEARCHSPLOIT]


def _buscar_exploitdb(termino: str, resultados: dict):
    """Ejecuta searchsploit para buscar exploits en Exploit-DB."""
    cmd = ["searchsploit", "--json", termino]

    try:
        proceso = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_COMANDO)
        salida  = proceso.stdout
        resultados["salida_raw"] += salida

        if proceso.returncode != 0 and not salida:
            resultados["errores"].append(f"searchsploit no encontró resultados para: {termino}")
            return

        _parsear_json_searchsploit(salida, termino, resultados)

    except FileNotFoundError:
        resultados["errores"].append("searchsploit no encontrado. Instalar con: apt install exploitdb")
    except subprocess.TimeoutExpired:
        resultados["errores"].append(f"Timeout buscando: {termino}")
    except Exception as e:
        resultados["errores"].append(f"Error en searchsploit para '{termino}': {str(e)}")


def _parsear_json_searchsploit(salida_json: str, termino_busqueda: str, resultados: dict):
    """Parsea la salida JSON de searchsploit y estructura los hallazgos."""
    try:
        datos    = json.loads(salida_json)
        exploits = datos.get("RESULTS_EXPLOIT", []) + datos.get("RESULTS_SHELLCODE", [])

        for exploit in exploits:
            titulo = exploit.get("Title", "")
            ruta   = exploit.get("Path", "")
            tipo   = exploit.get("Type", "")
            fecha  = exploit.get("Date_Published", "")
            cve    = _extraer_cve(exploit.get("Codes", ""), titulo)

            codigo_owasp, nombre_owasp = _mapear_owasp(titulo)

            vulnerabilidad = {
                "titulo"          : titulo,
                "cve"             : cve,
                "termino_busqueda": termino_busqueda,
                "ruta"            : ruta,
                "tipo"            : tipo,
                "fecha"           : fecha,
                "severidad"       : _clasificar_severidad(titulo),
                "codigo_owasp"    : codigo_owasp,
                "nombre_owasp"    : nombre_owasp,
                "recomendacion"   : _generar_recomendacion(titulo)
            }
            resultados["vulnerabilidades"].append(vulnerabilidad)

    except (json.JSONDecodeError, KeyError) as e:
        resultados["errores"].append(f"Error parseando searchsploit JSON: {str(e)}")


def _extraer_cve(codes: str, titulo: str) -> str:
    """
    Extrae el CVE asociado a un exploit.
    Prioriza el campo 'Codes' del JSON; si está vacío busca en el título.
    Devuelve el primer CVE encontrado o 'N/A'.
    """
    patron = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

    coincidencia = patron.search(codes)
    if coincidencia:
        return coincidencia.group(0).upper()

    coincidencia = patron.search(titulo)
    if coincidencia:
        return coincidencia.group(0).upper()

    return "N/A"


def _mapear_owasp(titulo: str) -> tuple:
    """Mapea el título de un exploit a su categoría del OWASP Top 10 2021."""
    titulo_minuscula = titulo.lower()
    for palabra_clave, (codigo, nombre) in MAPEO_OWASP.items():
        if palabra_clave in titulo_minuscula:
            return codigo, nombre
    return OWASP_CATEGORIA_DEFECTO


def _clasificar_severidad(titulo: str) -> str:
    """Clasifica la severidad de un exploit según palabras clave en su título."""
    titulo_minuscula = titulo.lower()
    for severidad, palabras in PALABRAS_CLAVE_SEVERIDAD.items():
        if any(p in titulo_minuscula for p in palabras):
            return severidad
    return SEVERIDAD_DEFECTO


def _generar_recomendacion(titulo: str) -> str:
    """Genera una recomendación de mitigación basada en el tipo de vulnerabilidad."""
    t = titulo.lower()

    if any(k in t for k in ["rce", "remote code"]):
        return (
            "Actualizar el componente afectado a la última versión estable. "
            "Implementar validación y saneamiento estricto de entradas de usuario. "
            "Revisar permisos de ejecución en el servidor."
        )
    if any(k in t for k in ["sql", "sqli"]):
        return (
            "Usar consultas parametrizadas o prepared statements. "
            "Nunca construir consultas SQL concatenando entrada del usuario. "
            "Aplicar el principio de mínimo privilegio en el usuario de base de datos."
        )
    if "xss" in t or "cross-site scripting" in t:
        return (
            "Sanitizar y codificar toda la salida hacia el navegador. "
            "Implementar Content Security Policy (CSP). "
            "Usar atributo HttpOnly en cookies de sesión."
        )
    if any(k in t for k in ["lfi", "local file"]):
        return (
            "Nunca usar entrada del usuario en funciones de inclusión de archivos. "
            "Implementar una lista blanca de archivos permitidos. "
            "Deshabilitar allow_url_include en PHP."
        )
    if "privilege" in t or "escalation" in t:
        return (
            "Aplicar el principio de mínimo privilegio. "
            "Mantener el sistema operativo actualizado con los últimos parches. "
            "Revisar permisos de binarios SUID y configuraciones sudo."
        )
    return (
        "Actualizar el componente a la última versión disponible. "
        "Revisar la configuración de seguridad del servicio afectado. "
        "Consultar el advisory oficial del CVE para medidas específicas."
    )


def _contar_por_severidad(resultados: dict):
    """Contabiliza vulnerabilidades por nivel de severidad."""
    mapa_contadores = {
        "critica": "cantidad_criticas",
        "alta"   : "cantidad_altas",
        "media"  : "cantidad_medias",
        "baja"   : "cantidad_bajas",
    }
    for vuln in resultados["vulnerabilidades"]:
        clave = mapa_contadores.get(vuln.get("severidad", "media"), "cantidad_medias")
        resultados[clave] += 1


def _construir_resumen_owasp(resultados: dict):
    """Agrupa los hallazgos por categoría OWASP para el informe."""
    for vuln in resultados["vulnerabilidades"]:
        codigo = vuln.get("codigo_owasp", OWASP_CATEGORIA_DEFECTO[0])
        nombre = vuln.get("nombre_owasp", OWASP_CATEGORIA_DEFECTO[1])
        clave  = f"{codigo} - {nombre}"

        if clave not in resultados["hallazgos_owasp"]:
            resultados["hallazgos_owasp"][clave] = []
        resultados["hallazgos_owasp"][clave].append({
            "cve"   : vuln.get("cve", "N/A"),
            "titulo": vuln["titulo"]
        })


def _imprimir_resumen_vulnerabilidades(resultados: dict):
    """Imprime el resumen de vulnerabilidades encontradas."""
    total = len(resultados["vulnerabilidades"])

    print(f"\n    [+] Resumen de vulnerabilidades:")
    print(f"        Total encontradas : {total}")

    if total > 0:
        print(f"        {Colores.ERROR}Criticas : {resultados['cantidad_criticas']}{Colores.FIN}")
        print(f"        Altas    : {resultados['cantidad_altas']}")
        print(f"        Medias   : {resultados['cantidad_medias']}")
        print(f"        Bajas    : {resultados['cantidad_bajas']}")

        print(f"\n        Clasificación OWASP Top 10:")
        for categoria_owasp, hallazgos in sorted(resultados["hallazgos_owasp"].items()):
            print(f"\n          [{categoria_owasp}]  ({len(hallazgos)} hallazgos)")
            for h in hallazgos:
                cve_str = f"[{h['cve']}]" if h['cve'] != "N/A" else "[Sin CVE]"
                print(f"            {cve_str} {h['titulo']}")

    for error in resultados["errores"]:
        print(f"        {Colores.ERROR}[!] {error}{Colores.FIN}")
