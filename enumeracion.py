# =============================================================================
# AuditX - enumeracion.py
# =============================================================================
# Fase 3: Enumeración de directorios y archivos mediante ffuf.
# =============================================================================

import subprocess
import json
import os
from configuracion import (Colores, TIMEOUT_FFUF, WORDLIST_DEFECTO, WORDLIST_SISTEMA,
                           EXTENSIONES_FUZZ, FFUF_HILOS, FFUF_TIMEOUT_PETICION,
                           FFUF_CODIGOS_ESTADO, FFUF_ARCHIVO_SALIDA)


def ejecutar_enumeracion(objetivo: str, puertos: list, wordlist: str = None, timeout_fuzz: int = None) -> dict:
    """
    Realiza fuzzing de directorios y archivos sobre los puertos web detectados.

    Args:
        objetivo     : IP o hostname del objetivo.
        puertos      : Lista de puertos del módulo descubrimiento.
        wordlist     : Ruta a una wordlist personalizada (opcional).
        timeout_fuzz : Timeout en segundos para ffuf (opcional).

    Returns:
        Diccionario con rutas descubiertas y su información.
    """
    print(f"\n[*] MÓDULO — Fuzzing de directorios y archivos")

    resultados = {
        "hallazgos"     : [],
        "interesantes"  : [],
        "urls_fuzzeadas": [],
        "wordlist_usada": "",
        "salida_raw"    : "",
        "errores"       : []
    }

    lista_palabras = _resolver_wordlist(wordlist)
    if not lista_palabras:
        mensaje = "No se encontró wordlist. Coloca una en wordlists/ o instala seclists."
        print(f"    {Colores.ERROR}[!] {mensaje}{Colores.FIN}")
        resultados["errores"].append(mensaje)
        return resultados

    resultados["wordlist_usada"] = lista_palabras
    print(f"    Wordlist : {lista_palabras}")

    timeout  = timeout_fuzz if timeout_fuzz else TIMEOUT_FFUF
    urls_web = _construir_urls_web(objetivo, puertos)

    if not urls_web:
        print(f"    [!] No se detectaron puertos web abiertos. Fuzzing omitido.")
        return resultados

    for url in urls_web:
        resultados["urls_fuzzeadas"].append(url)
        print(f"    [~] Fuzzing sobre: {url}  (timeout: {timeout}s)")
        _ejecutar_ffuf(url, lista_palabras, resultados, timeout)

    _clasificar_interesantes(resultados)
    _imprimir_resumen_enumeracion(resultados)
    return resultados


def _resolver_wordlist(personalizada: str = None) -> str:
    """
    Resuelve qué wordlist usar por orden de prioridad:
    1. Wordlist especificada por el usuario (-w)
    2. Wordlist local del proyecto (wordlists/default.txt)
    3. Fallback del sistema (/usr/share/wordlists/dirb/common.txt)
    """
    if personalizada:
        if os.path.exists(personalizada):
            return personalizada
        print(f"    {Colores.ERROR}[!] Wordlist indicada no encontrada: {personalizada}{Colores.FIN}")
    if os.path.exists(WORDLIST_DEFECTO):
        return WORDLIST_DEFECTO
    if os.path.exists(WORDLIST_SISTEMA):
        return WORDLIST_SISTEMA
    return ""


def _construir_urls_web(objetivo: str, puertos: list) -> list:
    """Construye las URLs base para hacer fuzzing según los puertos web abiertos."""
    from configuracion import PUERTOS_WEB
    urls = []

    if not puertos:
        return []

    numeros_puerto = []
    if isinstance(puertos[0], dict):
        numeros_puerto = [p["puerto"] for p in puertos if p.get("es_web") or p["puerto"] in PUERTOS_WEB]
    else:
        numeros_puerto = [p for p in puertos if p in PUERTOS_WEB]

    for puerto in numeros_puerto:
        esquema = "https" if puerto in [443, 8443] else "http"
        if puerto in [80, 443]:
            urls.append(f"{esquema}://{objetivo}")
        else:
            urls.append(f"{esquema}://{objetivo}:{puerto}")

    return urls


def _ejecutar_ffuf(url_base: str, wordlist: str, resultados: dict, timeout: int = TIMEOUT_FFUF):
    """Ejecuta ffuf sobre la URL base buscando directorios y archivos."""
    # -maxtime hace que ffuf se detenga limpiamente antes del timeout externo
    # y escriba el JSON de resultados parciales antes de salir.
    # Se usa un margen de 10 s para que ffuf termine antes de que el subprocess lo mate.
    maxtime_ffuf = max(timeout - 10, 30)

    cmd = [
        "ffuf",
        "-u",        f"{url_base}/FUZZ",
        "-w",        wordlist,
        "-e",        EXTENSIONES_FUZZ,
        "-ic",
        "-o",        FFUF_ARCHIVO_SALIDA,
        "-of",       "json",
        "-mc",       FFUF_CODIGOS_ESTADO,
        "-t",        str(FFUF_HILOS),
        "-timeout",  str(FFUF_TIMEOUT_PETICION),
        "-maxtime",  str(maxtime_ffuf),
    ]

    try:
        proceso = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        resultados["salida_raw"] += proceso.stdout
        _parsear_json_ffuf(FFUF_ARCHIVO_SALIDA, url_base, resultados)

    except FileNotFoundError:
        resultados["errores"].append("ffuf no encontrado. Instalar con: apt install ffuf")
    except subprocess.TimeoutExpired:
        # Aunque raro con -maxtime, se intenta recuperar resultados parciales
        _parsear_json_ffuf(FFUF_ARCHIVO_SALIDA, url_base, resultados)
        resultados["errores"].append(f"ffuf superó el timeout de {timeout}s en {url_base} (resultados parciales)")
    except Exception as e:
        resultados["errores"].append(f"Error en ffuf sobre {url_base}: {str(e)}")
    finally:
        if os.path.exists(FFUF_ARCHIVO_SALIDA):
            os.remove(FFUF_ARCHIVO_SALIDA)


def _parsear_json_ffuf(archivo_json: str, url_base: str, resultados: dict):
    """Parsea el JSON de salida de ffuf y añade los hallazgos al resultado."""
    if not os.path.exists(archivo_json):
        return

    try:
        with open(archivo_json, "r") as f:
            datos = json.load(f)

        for entrada in datos.get("results", []):
            hallazgo = {
                "url"     : f"{url_base}/{entrada.get('input', {}).get('FUZZ', '')}",
                "estado"  : entrada.get("status", 0),
                "tamano"  : entrada.get("length", 0),
                "palabras": entrada.get("words", 0),
                "lineas"  : entrada.get("lines", 0)
            }
            resultados["hallazgos"].append(hallazgo)

    except (json.JSONDecodeError, KeyError) as e:
        resultados["errores"].append(f"Error parseando salida de ffuf: {str(e)}")


def _clasificar_interesantes(resultados: dict):
    """Clasifica los hallazgos como interesantes según estado y nombre."""
    patrones_sensibles = [
        "config", "admin", "backup", "db", "database", "install",
        "setup", ".env", ".git", "passwd", "secret", "key", "token",
        "login", "panel", "phpmyadmin", "wp-admin", "manager"
    ]

    for hallazgo in resultados["hallazgos"]:
        url_minuscula = hallazgo["url"].lower()
        es_sensible   = any(p in url_minuscula for p in patrones_sensibles)
        if hallazgo["estado"] == 200 or es_sensible:
            resultados["interesantes"].append(hallazgo)


def _imprimir_resumen_enumeracion(resultados: dict):
    """Imprime el resumen de la enumeración."""
    total        = len(resultados["hallazgos"])
    interesantes = len(resultados["interesantes"])

    print(f"\n    [+] Resumen de enumeración:")
    print(f"        Total de rutas descubiertas : {total}")
    print(f"        Rutas de interes            : {interesantes}")

    if resultados["hallazgos"]:
        urls_interesantes = {h["url"] for h in resultados["interesantes"]}
        print(f"\n        Rutas descubiertas:")
        for hallazgo in resultados["hallazgos"]:
            marca = " *" if hallazgo["url"] in urls_interesantes else ""
            print(f"          [{hallazgo['estado']}] {hallazgo['url']} ({hallazgo['tamano']} bytes){marca}")

    for error in resultados["errores"]:
        print(f"        {Colores.ERROR}[!] {error}{Colores.FIN}")
