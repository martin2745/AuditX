# =============================================================================
# AuditX - configuracion.py
# =============================================================================
# Configuración global de la herramienta: rutas, timeouts, flags y colores.
# =============================================================================

import os

# --- Timeouts en segundos ---
TIMEOUT_NMAP = 300   # 5 minutos para escaneo de puertos
# --- Puertos web de interés ---
PUERTOS_WEB = [80, 443, 8080, 8443, 8000, 8888]


# --- Colores para la salida por consola (códigos ANSI) ---
class Colores:
    CABECERA    = '\033[95m'
    AZUL        = '\033[94m'
    CIAN        = '\033[96m'
    VERDE       = '\033[92m'
    ADVERTENCIA = '\033[93m'
    ERROR       = '\033[91m'
    FIN         = '\033[0m'
    NEGRITA     = '\033[1m'


# --- Banner de la herramienta ---
BANNER = f"""
{Colores.CIAN}{Colores.NEGRITA}
  █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗
 ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝╚██╗██╔╝
 ███████║██║   ██║██║  ██║██║   ██║    ╚███╔╝
 ██╔══██║██║   ██║██║  ██║██║   ██║    ██╔██╗
 ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██╔╝ ██╗
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝
{Colores.FIN}
{Colores.VERDE}  [ Herramienta modular de auditoría de hosts y redes ]{Colores.FIN}
{Colores.ADVERTENCIA}  [ Uso exclusivo en entornos controlados y con autorización ]{Colores.FIN}
  Autor  : Martín Gil Blanco
  TFM    : Máster en Ciberseguridad - Universidad Isabel I
  Versión: 1.0.0
"""
