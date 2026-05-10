# AuditX

**Herramienta modular de auditoría web automatizada**

> Desarrollada como parte del Trabajo Fin de Máster en Ciberseguridad  
> Universidad Internacional Isabel I de Castilla — Curso 2025/26  
> Autor: Martín Gil Blanco

---

## Aviso Legal

Esta herramienta ha sido desarrollada con fines **exclusivamente académicos y de investigación**.  
Su uso está permitido **únicamente sobre sistemas propios o con autorización explícita por escrito**.  
El uso no autorizado sobre sistemas ajenos es ilegal y puede conllevar responsabilidad penal.

---

## Descripción

AuditX automatiza las fases de una auditoría de seguridad web siguiendo las metodologías **PTES** (Penetration Testing Execution Standard) y **OWASP WSTG** (Web Security Testing Guide).

---

## Arquitectura

```
AuditX/
│
├── main.py                          # Punto de entrada y orquestador
├── configuracion.py                 # Configuración global (rutas, timeouts, colores)
│
├── escaneo_red.py                   # Fase 0: Descubrimiento de hosts en red (nmap -sn)
├── descubrimiento.py                # Fase 1: Escaneo de puertos (nmap)
...
└── informes/                        # Informes generados automáticamente
```

## Requisitos

### Sistema operativo

- Kali Linux (recomendado) o cualquier distribución Linux con las herramientas necesarias

### Herramientas externas

```bash
sudo apt update
sudo apt install -y nmap whatweb ffuf exploitdb seclists curl
```

> AuditX verifica automáticamente al arrancar que todas las herramientas están instaladas
> e indica el comando exacto para instalar las que falten.

### Python

- Python 3.8 o superior
- Sin dependencias externas (usa únicamente la librería estándar)

---

## Instalación

```bash
git clone https://github.com/tu-usuario/AuditX.git
cd AuditX
```

---

## Uso

### Modo interactivo (recomendado)

```bash
sudo python3 main.py
```

Al arrancar sin argumentos se muestra el menú principal:

```bash
============================================================
  ¿Qué deseas hacer?
============================================================
  [1]  Escanear la red y elegir objetivo
  [2]  Auditar una máquina directamente
  [q]  Salir
============================================================
```

- **Opción 1:** Pide el rango de red (CIDR), descubre hosts activos, muestra la lista numerada y permite elegir cuál auditar. Al finalizar pregunta si se quiere auditar otro host.
- **Opción 2:** Pide la IP directamente, audita y termina.

### Atajos por línea de comandos

```bash
# Auditar una máquina directamente
sudo python3 main.py -t 192.168.1.10

# Escanear red y elegir objetivo de forma interactiva
sudo python3 main.py -n 192.168.100.0/24
```

### Todas las opciones disponibles

```bash
Objetivo (mutuamente excluyentes):
  -t, --objetivo    IP o hostname del objetivo
  -n, --red         Rango de red en CIDR (ej: 192.168.100.0/24)

Opciones de módulos:
  --sigiloso        Escaneo sigiloso TCP SYN (requiere sudo)
  --omitir-enum     Omitir fase de enumeración de directorios
  --omitir-vuln     Omitir fase de búsqueda de vulnerabilidades
  --omitir-informe  No generar informe al finalizar

Opciones de wordlist y tiempos:
  -w, --wordlist      Ruta a wordlist personalizada para ffuf
  --timeout-fuzz      Timeout máximo para ffuf en segundos (defecto: 600)

Opciones de salida:
  -o, --salida      Ruta personalizada para el informe
  -v, --verbose     Mostrar salida raw de las herramientas
```

## Fases de auditoría

| Fase | Módulo                          | Herramienta    | Descripción                                  |
|------|---------------------------------|----------------|----------------------------------------------|
| 0    | `escaneo_red.py`                | nmap -sn       | Ping sweep para descubrir hosts activos      |
| 1    | `descubrimiento.py`             | nmap           | Escaneo de puertos y detección de servicios  |

---

## Referencias

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [Exploit-DB](https://www.exploit-db.com/)