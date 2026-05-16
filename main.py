#!/usr/bin/env python3
# =============================================================================
# AuditX v1.0.0 — Herramienta modular de auditoría web automatizada
# =============================================================================
# Autor  : Martín Gil Blanco
# TFM    : Máster en Ciberseguridad — Universidad Isabel I de Castilla
# =============================================================================

import argparse
import sys
import os
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from configuracion              import (BANNER, Colores, DIRECTORIO_INFORMES,
                                        HERRAMIENTAS_REQUERIDAS, HERRAMIENTAS_OPCIONALES_FUZZ,
                                        TOTAL_FASES, ANCHO_SEPARADOR, ANCHO_AYUDA, POSICION_MAX_AYUDA)
from escaneo_red                import ejecutar_escaneo_red, seleccionar_objetivo, preguntar_continuar
from descubrimiento             import ejecutar_descubrimiento
from fingerprinting             import ejecutar_fingerprinting
from enumeracion                import ejecutar_enumeracion
from busqueda_vulnerabilidades  import ejecutar_busqueda_vulnerabilidades
from generador_informe          import generar_informe


class FormateadorAyuda(argparse.RawTextHelpFormatter):
    """Formateador de ayuda que mantiene cada opción en una sola línea."""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=POSICION_MAX_AYUDA, width=ANCHO_AYUDA)


def verificar_herramientas(fuzz: bool = False):
    """Verifica que las herramientas externas necesarias estén disponibles."""
    herramientas = dict(HERRAMIENTAS_REQUERIDAS)
    if fuzz:
        herramientas.update(HERRAMIENTAS_OPCIONALES_FUZZ)

    faltantes = {h: cmd for h, cmd in herramientas.items() if not shutil.which(h)}
    if not faltantes:
        return
    print(f"\n{Colores.ERROR}[!] Herramientas no encontradas:{Colores.FIN}")
    for herramienta, cmd in faltantes.items():
        print(f"    {Colores.ERROR}x {herramienta}{Colores.FIN}  ->  {cmd}")
    print(f"\n    Instálalas y vuelve a ejecutar AuditX.\n")
    sys.exit(1)


def parsear_argumentos() -> argparse.Namespace:
    """Define y parsea los argumentos de línea de comandos (todos opcionales)."""
    parser = argparse.ArgumentParser(
        prog="AuditX",
        description=(
            "AuditX — Herramienta modular de auditoría web automatizada.\n"
            "Sin argumentos muestra el menú interactivo."
        ),
        formatter_class=FormateadorAyuda,
        epilog=(
            "Ejemplos:\n"
            "  python3 main.py                                                      # Menu interactivo\n"
            "  python3 main.py -n 192.168.100.0/24                                  # Escaneo de red\n"
            "  python3 main.py -t 192.168.1.10                                      # Audita directamente\n"
            "  python3 main.py -t 192.168.1.10 --sigiloso                           # Escaneo sigiloso\n"
            "  python3 main.py -t 192.168.1.10 --informe                            # Con informe Markdown\n"
            "  python3 main.py -t 192.168.1.10 --informe -o /tmp/informe.md         # Informe en ruta propia\n"
            "  python3 main.py -t 192.168.1.10 --fuzz                               # Con fuzzing web\n"
            "  python3 main.py -t 192.168.1.10 --fuzz -w /mi/wordlist.txt           # Fuzzing con wordlist propia\n"
            "  python3 main.py -t 192.168.1.10 --fuzz --timeout-fuzz 120            # Fuzzing con timeout reducido\n"
            "  python3 main.py -t 192.168.1.10 --omitir-vuln                        # Sin busqueda de vulnerabilidades\n"
            "  python3 main.py -t 192.168.1.10 --fuzz --informe                     # Fuzzing + informe\n"
            "  python3 main.py -t 192.168.1.10 --sigiloso --fuzz --informe          # Todo activado\n"
        )
    )

    grupo_objetivo = parser.add_mutually_exclusive_group(required=False)
    grupo_objetivo.add_argument("-t", "--objetivo", help="IP o hostname del objetivo (ej: 192.168.1.10)")
    grupo_objetivo.add_argument("-n", "--red", help="Rango de red en CIDR (ej: 192.168.100.0/24)")

    parser.add_argument("--sigiloso", action="store_true", default=False, help="Escaneo sigiloso TCP SYN")
    parser.add_argument("--fuzz", action="store_true", default=False, help="Activar fuzzing de directorios web (ffuf)")
    parser.add_argument("--omitir-vuln", action="store_true", default=False, help="Omitir busqueda de vulnerabilidades (searchsploit)")
    parser.add_argument("--informe", action="store_true", default=False, help="Generar informe Markdown al finalizar")
    parser.add_argument("-w", "--wordlist", default=None, help="Wordlist personalizada para ffuf (requiere --fuzz)")
    parser.add_argument("--timeout-fuzz", type=int, default=None, metavar="SEGUNDOS", help="Timeout para ffuf en segundos (por defecto: 600, requiere --fuzz)")
    parser.add_argument("-o", "--salida", default=None, help="Ruta personalizada para el informe (requiere --informe)")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Mostrar salida raw de las herramientas")

    return parser.parse_args()



# =============================================================================
# Menú interactivo de inicio
# =============================================================================

def mostrar_menu_inicio(args: argparse.Namespace):
    """Muestra el menú principal y delega al modo elegido."""
    print(f"\n{'='*ANCHO_SEPARADOR}")
    print(f"  ¿Que deseas hacer?")
    print(f"{'='*ANCHO_SEPARADOR}")
    print(f"  [1]  Escanear la red y elegir objetivo")
    print(f"  [2]  Auditar una maquina directamente")
    print(f"  [q]  Salir")
    print(f"{'='*ANCHO_SEPARADOR}")

    while True:
        try:
            opcion = input(f"\n  Opcion: ").strip().lower()
        except KeyboardInterrupt:
            print()
            sys.exit(0)

        if opcion == "1":
            _modo_red_menu(args)
            return
        elif opcion == "2":
            _modo_directo_menu(args)
            return
        elif opcion in ("q", "salir", "exit"):
            print(f"\n[!] Saliendo.\n")
            sys.exit(0)
        else:
            print(f"  {Colores.ERROR}[!] Opcion no valida. Introduce 1, 2 o q.{Colores.FIN}")


def _modo_red_menu(args: argparse.Namespace):
    """Flujo del modo red iniciado desde el menú."""
    try:
        red = input(f"\n  Introduce el rango de red (ej: 192.168.100.0/24): ").strip()
    except KeyboardInterrupt:
        print()
        return

    if not red:
        print(f"  {Colores.ERROR}[!] Rango de red vacio.{Colores.FIN}")
        return

    args.red = red
    modo_red(args)


def _modo_directo_menu(args: argparse.Namespace):
    """Flujo del modo directo iniciado desde el menú."""
    try:
        objetivo = input(f"\n  Introduce la IP o hostname del objetivo: ").strip()
    except KeyboardInterrupt:
        print()
        return

    if not objetivo:
        print(f"  {Colores.ERROR}[!] IP vacia.{Colores.FIN}")
        return

    auditar_objetivo(objetivo, args)


# =============================================================================
# Modos de ejecución
# =============================================================================

def modo_red(args: argparse.Namespace):
    """Escanea la red, permite elegir objetivo y auditar en bucle."""
    hosts = ejecutar_escaneo_red(args.red)

    if not hosts:
        print(f"{Colores.ERROR}[!] No se encontraron hosts activos en {args.red}.{Colores.FIN}\n")
        return

    objetivo = seleccionar_objetivo(hosts)
    if not objetivo:
        print(f"\n[!] Saliendo.\n")
        return

    while objetivo:
        auditar_objetivo(objetivo, args)
        objetivo = preguntar_continuar(hosts)

    print(f"\n[+] Sesion de auditoria finalizada.\n")


# =============================================================================
# Pipeline de auditoría
# =============================================================================

def imprimir_separador_fase(numero_fase: int, nombre_fase: str):
    print(f"\n{'='*ANCHO_SEPARADOR}")
    print(f" [{numero_fase}/{TOTAL_FASES}] {nombre_fase}")
    print(f"{'='*ANCHO_SEPARADOR}")


def confirmar_objetivo(objetivo: str) -> bool:
    """Solicita confirmación explícita antes de iniciar el análisis."""
    print(f"\n{'='*ANCHO_SEPARADOR}")
    print("  AVISO DE USO RESPONSABLE")
    print(f"{'='*ANCHO_SEPARADOR}")
    print(f"  Objetivo : {objetivo}")
    print(
        f"\n  Esta herramienta debe usarse ÚNICAMENTE en sistemas"
        f"\n  para los que tienes autorización."
    )
    print(f"\n{'='*ANCHO_SEPARADOR}")
    try:
        respuesta = input("\n  ¿Confirmas que tienes autorización? [s/N]: ").strip().lower()
        return respuesta in ["s", "si", "sí", "yes", "y"]
    except KeyboardInterrupt:
        return False


def auditar_objetivo(objetivo: str, args: argparse.Namespace):
    """Ejecuta el pipeline completo de auditoría sobre un objetivo."""
    hora_inicio = datetime.now()

    if not confirmar_objetivo(objetivo):
        print(f"\n{Colores.ERROR}[!] Auditoria cancelada.{Colores.FIN}\n")
        return

    print(f"\n[+] Iniciando auditoria sobre: {objetivo}")
    print(f"    Hora de inicio: {hora_inicio.strftime('%H:%M:%S')}")

    # FASE 1
    imprimir_separador_fase(1, "Descubrimiento de puertos y servicios")
    resultados_descubrimiento = ejecutar_descubrimiento(objetivo, sigiloso=args.sigiloso)
    if args.verbose and resultados_descubrimiento.get("salida_raw"):
        print(f"\n[RAW - nmap]\n{resultados_descubrimiento['salida_raw']}")

    # FASE 2
    imprimir_separador_fase(2, "Fingerprinting de servicios")
    resultados_fingerprinting = ejecutar_fingerprinting(objetivo, resultados_descubrimiento.get("puertos", []))
    if args.verbose and resultados_fingerprinting.get("salida_raw"):
        print(f"\n[RAW - fingerprinting]\n{resultados_fingerprinting['salida_raw']}")

    # MÓDULO OPCIONAL — Fuzzing web
    resultados_enumeracion = {"hallazgos": [], "interesantes": [], "urls_fuzzeadas": [], "wordlist_usada": "N/A", "salida_raw": "", "errores": []}
    if args.fuzz:
        print(f"\n{'='*ANCHO_SEPARADOR}")
        print(f" [+] MÓDULO OPCIONAL — Fuzzing de directorios web")
        print(f"{'='*ANCHO_SEPARADOR}")
        resultados_enumeracion = ejecutar_enumeracion(
            objetivo,
            resultados_descubrimiento.get("puertos", []),
            wordlist=args.wordlist,
            timeout_fuzz=args.timeout_fuzz
        )
        if args.verbose and resultados_enumeracion.get("salida_raw"):
            print(f"\n[RAW - ffuf]\n{resultados_enumeracion['salida_raw']}")

    # FASE 3
    if not args.omitir_vuln:
        imprimir_separador_fase(3, "Busqueda de vulnerabilidades conocidas")
        resultados_vulnerabilidades = ejecutar_busqueda_vulnerabilidades(resultados_descubrimiento, resultados_fingerprinting)
    else:
        print(f"\n[~] Fase 3 omitida (--omitir-vuln)")
        resultados_vulnerabilidades = {"vulnerabilidades": [], "hallazgos_owasp": {}, "errores": []}
   
    # Informe    
    ruta_informe = None
    if args.informe:
        ruta_informe = generar_informe(
            objetivo                    = objetivo,
            resultados_descubrimiento   = resultados_descubrimiento,
            resultados_fingerprinting   = resultados_fingerprinting,
            resultados_enumeracion      = resultados_enumeracion,
            resultados_vulnerabilidades = resultados_vulnerabilidades
        )

     # Resumen final
    hora_fin     = datetime.now()
    duracion     = hora_fin - hora_inicio
    total_vulns  = len(resultados_vulnerabilidades.get("vulnerabilidades", []))

    print(f"\n{'='*ANCHO_SEPARADOR}")
    print(f" AUDITORIA COMPLETADA")
    print(f"{'='*ANCHO_SEPARADOR}")
    print(f"  Objetivo    : {objetivo}")
    print(f"  Duracion    : {str(duracion).split('.')[0]}")
    print(f"  Puertos     : {len(resultados_descubrimiento.get('puertos', []))}")
    print(f"  Servicios   : {len(resultados_fingerprinting.get('servicios', {}))}")
    print(f"  Tecnologias : {len(resultados_fingerprinting.get('tecnologias', []))}")
    print(f"  Directorios : {len(resultados_enumeracion.get('hallazgos', []))}")
    aviso_vuln = " <-- revisar" if total_vulns > 0 else ""
    print(f"  Vulnerab.   : {total_vulns}{aviso_vuln}")
    if ruta_informe:
        print(f"\n  Informe: {ruta_informe}")
    print(f"{'='*ANCHO_SEPARADOR}\n")
    

# =============================================================================
# Entrada principal
# =============================================================================

def principal():
    try:
        args = parsear_argumentos()
        verificar_herramientas(fuzz=args.fuzz)
        print(BANNER)

        if args.objetivo:
            auditar_objetivo(args.objetivo, args)
        elif args.red:
            modo_red(args)
        else:
            mostrar_menu_inicio(args)

    except KeyboardInterrupt:
        print(f"\n\n[!] Interrumpido por el usuario.\n")
        sys.exit(1)
    except PermissionError:
        print(f"\n{Colores.ERROR}[!] Error de permisos. Ejecuta con sudo.{Colores.FIN}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colores.ERROR}[!] Error inesperado: {str(e)}{Colores.FIN}\n")
        raise


if __name__ == "__main__":
    principal()
