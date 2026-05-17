# =============================================================================
# AuditX - generador_informe.py
# =============================================================================
# Genera el informe final de auditoría en formato Markdown con índice navegable.
# =============================================================================

import os
from datetime import datetime
from configuracion import DIRECTORIO_INFORMES


def generar_informe(
    objetivo                    : str,
    resultados_descubrimiento   : dict,
    resultados_fingerprinting   : dict,
    resultados_enumeracion      : dict,
    resultados_vulnerabilidades : dict
) -> str:
    """
    Genera el informe completo de auditoría en Markdown.

    Returns:
        Ruta al archivo de informe generado.
    """
    print(f"\n[*] Generando informe de auditoria...")

    os.makedirs(DIRECTORIO_INFORMES, exist_ok=True)

    marca_tiempo  = datetime.now().strftime("%Y%m%d_%H%M%S")
    objetivo_limpio = objetivo.replace(".", "_").replace(":", "_")
    nombre_archivo  = f"AuditX_Informe_{objetivo_limpio}_{marca_tiempo}.md"
    ruta_archivo    = os.path.join(DIRECTORIO_INFORMES, nombre_archivo)

    contenido = _construir_informe(
        objetivo, marca_tiempo,
        resultados_descubrimiento,
        resultados_fingerprinting,
        resultados_enumeracion,
        resultados_vulnerabilidades
    )

    with open(ruta_archivo, "w", encoding="utf-8") as f:
        f.write(contenido)

    print(f"    [+] Informe generado: {ruta_archivo}")
    return ruta_archivo


def _construir_informe(objetivo, marca_tiempo, descubrimiento, fingerprinting, enumeracion, vulnerabilidades) -> str:
    """Construye el contenido completo del informe en Markdown."""
    fecha_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    hay_owasp = bool(vulnerabilidades.get("hallazgos_owasp"))

    secciones = [
        _seccion_cabecera(objetivo),
        _seccion_indice(hay_owasp),
        _seccion_resumen(objetivo, fecha_str, descubrimiento, fingerprinting, vulnerabilidades),
        _seccion_descubrimiento(descubrimiento),
        _seccion_fingerprinting(fingerprinting),
        _seccion_enumeracion(enumeracion),
    ]

    if hay_owasp:
        secciones.append(_seccion_owasp(vulnerabilidades))

    secciones.append(_seccion_vulnerabilidades(vulnerabilidades))

    return "\n\n".join(secciones)


# =============================================================================
# Secciones del informe
# =============================================================================


def _seccion_cabecera(objetivo: str) -> str:
    return f"# Informe de Auditoria de Seguridad de {objetivo}"


def _seccion_indice(hay_owasp: bool) -> str:
    entradas = [
        "1. [Resumen Ejecutivo](#1-resumen-ejecutivo)",
        "2. [Descubrimiento de Puertos y Servicios](#2-descubrimiento-de-puertos-y-servicios)",
        "3. [Fingerprinting de Servicios](#3-fingerprinting-de-servicios)",
        "4. [Enumeracion de Directorios y Archivos](#4-enumeracion-de-directorios-y-archivos)",
    ]

    if hay_owasp:
        entradas.append("5. [Clasificacion OWASP Top 10 2021](#5-clasificacion-owasp-top-10-2021)")
        entradas.append("6. [Vulnerabilidades Identificadas](#6-vulnerabilidades-identificadas)")
    else:
        entradas.append("5. [Vulnerabilidades Identificadas](#5-vulnerabilidades-identificadas)")

    cuerpo_indice = "\n".join(entradas)

    return f"""## Indice

{cuerpo_indice}

---"""


def _seccion_resumen(objetivo, fecha_str, descubrimiento, fingerprinting, vulnerabilidades) -> str:
    total_puertos = len(descubrimiento.get("puertos", []))
    total_techs   = len(fingerprinting.get("tecnologias", []))
    total_vulns   = len(vulnerabilidades.get("vulnerabilidades", []))
    criticas      = vulnerabilidades.get("cantidad_criticas", 0)
    altas         = vulnerabilidades.get("cantidad_altas", 0)

    if criticas > 0:
        nivel_riesgo = "CRITICO"
    elif altas > 0:
        nivel_riesgo = "ALTO"
    else:
        nivel_riesgo = "MEDIO"

    info_cms = ""
    if fingerprinting.get("cms"):
        info_cms = f"\n**CMS detectado:** {fingerprinting['cms']} {fingerprinting.get('version_cms', '')}"

    return f"""## 1. Resumen Ejecutivo

| Parametro               | Valor                         |
|-------------------------|-------------------------------|
| Objetivo                | {objetivo}                    |
| Fecha de analisis       | {fecha_str}                   |
| Sistema operativo       | {descubrimiento.get('sistema_operativo', 'Desconocido')} |
| Puertos abiertos        | {total_puertos}               |
| Tecnologias detectadas  | {total_techs}                 |
| Vulnerabilidades        | {total_vulns}                 |
| Nivel de riesgo         | **{nivel_riesgo}**            |
{info_cms}

### Distribucion de vulnerabilidades por severidad

| Severidad | Cantidad |
|-----------|----------|
| Critica   | {criticas} |
| Alta      | {altas} |
| Media     | {vulnerabilidades.get('cantidad_medias', 0)} |
| Baja      | {vulnerabilidades.get('cantidad_bajas', 0)} |"""


def _seccion_descubrimiento(descubrimiento: dict) -> str:
    tabla_puertos = ""
    for p in descubrimiento.get("puertos", []):
        es_web = "Si" if p.get("es_web") else "No"
        tabla_puertos += (
            f"| {p['puerto']}/{p['protocolo']} "
            f"| {p['estado']} "
            f"| {p['servicio']} "
            f"| {p.get('version', 'N/A')} "
            f"| {es_web} |\n"
        )

    if not tabla_puertos:
        tabla_puertos = "| — | — | — | — | — |\n"

    metadatos_http = descubrimiento.get("metadatos_http", {})
    seccion_meta = ""
    if metadatos_http:
        seccion_meta = f"""
### Metadatos HTTP detectados

| Campo     | Valor                     |
|-----------|---------------------------|
| Titulo    | {metadatos_http.get('titulo', 'N/A')} |
| Generador | {metadatos_http.get('generador', 'N/A')} |
| Servidor  | {metadatos_http.get('servidor', 'N/A')} |"""

    return f"""## 2. Descubrimiento de Puertos y Servicios

**Sistema operativo detectado:** {descubrimiento.get('sistema_operativo', 'Desconocido')}

### Puertos y servicios abiertos

| Puerto     | Estado | Servicio | Version | Web |
|------------|--------|----------|---------|-----|
{tabla_puertos}
{seccion_meta}"""


def _seccion_fingerprinting(fingerprinting: dict) -> str:
    # Tabla de servicios analizados
    servicios = fingerprinting.get("servicios", {})
    if servicios:
        tabla_servicios = "| Servicio | Puerto | Detalle |\n|----------|--------|---------|\n"
        for clave, info in servicios.items():
            tipo, puerto = clave.split(":", 1)
            detalle = (
                info.get("version")
                or info.get("banner", "")
                or info.get("url", "")
                or "–"
            )
            if isinstance(detalle, str):
                detalle = detalle[:80]
            tabla_servicios += f"| `{tipo.upper()}` | {puerto} | {detalle} |\n"
    else:
        tabla_servicios = "_No se analizaron servicios._"

    # Tecnologías identificadas
    lista_techs = "\n".join(
        [f"- {t}" for t in fingerprinting.get("tecnologias", [])]
    ) or "- No identificadas"

    # Acceso anónimo FTP (si aplica)
    ftp_anonimo = ""
    for clave, info in servicios.items():
        if clave.startswith("ftp") and info.get("anonimo"):
            archivos = info.get("archivos_raiz", [])
            ftp_anonimo = f"\n> **[!] Login anónimo FTP habilitado.** Archivos raíz: `{', '.join(archivos[:5]) or 'N/A'}`\n"

    # SMB signing (si aplica)
    smb_warning = ""
    for clave, info in servicios.items():
        if clave.startswith("smb") and info.get("firmar") == "disabled":
            smb_warning = "\n> **[!] SMB message signing deshabilitado** — riesgo de ataques relay.\n"

    # Sección web: CMS y cabeceras de seguridad (solo si hay servicios HTTP/HTTPS)
    hay_web = any(k.startswith(("http", "https")) for k in servicios)
    seccion_web = ""
    if hay_web:
        seguridad    = fingerprinting.get("cabeceras_seguridad", {})
        presentes    = seguridad.get("presentes", [])
        ausentes     = seguridad.get("ausentes", [])
        presentes_md = "\n".join([f"- [PRESENTE] `{h}`" for h in presentes]) or "- Ninguna"
        ausentes_md  = "\n".join([f"- [AUSENTE]  `{h}`" for h in ausentes])  or "- Ninguna"

        cms_info = ""
        if fingerprinting.get("cms"):
            cms_info = f"\n**CMS detectado:** {fingerprinting['cms']} {fingerprinting.get('version_cms', '')}"

        seccion_web = f"""
### Servicios web{cms_info}

**Servidor web:** {fingerprinting.get('servidor_web', 'No detectado')}

#### Cabeceras de seguridad HTTP (OWASP A05)

> Las cabeceras ausentes constituyen una **Security Misconfiguration (A05)**.

**Presentes:**
{presentes_md}

**Ausentes (recomendadas):**
{ausentes_md}"""

    return f"""## 3. Fingerprinting de Servicios

### Servicios analizados

{tabla_servicios}{ftp_anonimo}{smb_warning}
### Tecnologias identificadas

{lista_techs}{seccion_web}"""


def _seccion_enumeracion(enumeracion: dict) -> str:
    wordlist   = enumeracion.get("wordlist_usada", "N/A")
    hallazgos  = enumeracion.get("hallazgos", [])
    interesantes = enumeracion.get("interesantes", [])
    errores    = enumeracion.get("errores", [])
    urls_fuzzeadas = enumeracion.get("urls_fuzzeadas", [])

    # Caso 1: módulo no ejecutado (wordlist = N/A y sin URLs fuzzeadas)
    if wordlist == "N/A" and not urls_fuzzeadas:
        return """## 4. Enumeracion de Directorios y Archivos

_Modulo de fuzzing no ejecutado. Usa `--fuzz` para activarlo._"""

    # Caso 2: sin URLs web detectadas (wordlist resuelta pero sin objetivos)
    if wordlist != "N/A" and not urls_fuzzeadas:
        return f"""## 4. Enumeracion de Directorios y Archivos

**Wordlist seleccionada:** `{wordlist}`

_No se detectaron puertos web abiertos en el objetivo. Fuzzing omitido._"""

    # Caso 3: fuzzing ejecutado — mostrar resultados (o ausencia de ellos)
    if errores:
        aviso_errores = "\n> **Avisos:** " + " | ".join(errores) + "\n"
    else:
        aviso_errores = ""

    if not hallazgos:
        hallazgos_md = "_ffuf no obtuvo respuestas con los codigos filtrados (200, 301, 302, 403)._"
    elif not interesantes:
        hallazgos_md = "_No se identificaron rutas de interes entre las descubiertas._"
    else:
        hallazgos_md = "| URL | Estado | Tamano |\n|-----|--------|--------|\n"
        for h in interesantes:
            hallazgos_md += f"| `{h['url']}` | {h['estado']} | {h['tamano']} bytes |\n"

    return f"""## 4. Enumeracion de Directorios y Archivos

**Wordlist utilizada:** `{wordlist}`
**URLs analizadas:** {', '.join(f'`{u}`' for u in urls_fuzzeadas) if urls_fuzzeadas else 'N/A'}
**Total de rutas descubiertas:** {len(hallazgos)}
**Rutas de interes:** {len(interesantes)}
{aviso_errores}
### Recursos destacados

{hallazgos_md}"""


def _seccion_vulnerabilidades(vulnerabilidades: dict) -> str:
    lista = vulnerabilidades.get("vulnerabilidades", [])
    num_seccion = 6 if vulnerabilidades.get("hallazgos_owasp") else 5

    if not lista:
        return f"""## {num_seccion}. Vulnerabilidades Identificadas

_No se encontraron exploits conocidos para las tecnologias detectadas._"""

    etiqueta_severidad = {
        "critica": "CRITICO",
        "alta"   : "ALTO",
        "media"  : "MEDIO",
        "baja"   : "BAJO",
    }

    lista_ordenada = sorted(lista, key=lambda v: v.get("codigo_owasp", "A99"))

    tarjetas_vulns = ""
    for vuln in lista_ordenada:
        severidad   = vuln.get("severidad", "media")
        texto_sev   = etiqueta_severidad.get(severidad, "MEDIO")
        badge_owasp = (
            f"`{vuln['codigo_owasp']}` {vuln['nombre_owasp']}"
            if vuln.get("codigo_owasp") else "N/A"
        )

        tarjetas_vulns += f"""
### [{texto_sev}] {vuln['titulo']}

| Campo           | Detalle                          |
|-----------------|----------------------------------|
| CVE             | {vuln.get('cve', 'N/A')}         |
| Severidad       | {texto_sev}                      |
| Busqueda        | `{vuln['termino_busqueda']}`     |
| Ruta exploit    | `{vuln.get('ruta', 'N/A')}`      |
| Tipo            | {vuln.get('tipo', 'N/A')}        |
| Fecha           | {vuln.get('fecha', 'N/A')}       |
| Categoria OWASP | {badge_owasp}                    |

---"""

    return f"""## {num_seccion}. Vulnerabilidades Identificadas

{tarjetas_vulns}"""


def _seccion_owasp(vulnerabilidades: dict) -> str:
    if not vulnerabilidades.get("hallazgos_owasp"):
        return ""

    cuerpo_owasp = ""
    for categoria, hallazgos in sorted(vulnerabilidades["hallazgos_owasp"].items()):
        cuerpo_owasp += f"\n### {categoria} ({len(hallazgos)} hallazgos)\n\n"
        for h in hallazgos:
            cve_str = f"`{h['cve']}`" if h['cve'] != "N/A" else "Sin CVE"
            cuerpo_owasp += f"- {cve_str} — {h['titulo']}\n"

    return f"""## 5. Clasificacion OWASP Top 10 2021

> Cada vulnerabilidad identificada ha sido mapeada a su categoria correspondiente
> del estandar OWASP Top 10 2021 para contextualizar el riesgo en el marco
> de referencia de la industria.

{cuerpo_owasp}"""


