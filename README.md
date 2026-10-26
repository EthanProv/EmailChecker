# EmailChecker — laboratorio antiphishing local ENTI-UB

Ethan Provencio, Josep Maria Poblet y Jhoan Lope. Implementado y comprobado en Windows el 26/10/2026.

Analizador de `.eml` con Python, señales estáticas, reputación opcional y Qwen3 local mediante Ollama. Incluye integración real con docker-mailserver/Postfix: los mensajes retenidos permanecen en la cola **HOLD** antes de llegar a Dovecot/INBOX. No se borran ni se reinyectan por nuestro filtro.

El repositorio incluye el código, las muestras sintéticas y las evidencias de inferencia de `results/review-real/`, además de `results/review-docker-tests.txt`. Los buzones, credenciales, certificados privados, auditorías de correo y registros del ordenador se mantienen exclusivamente en la instalación local. Las referencias del informe a otros resultados corresponden a esa instalación.

## Uso inmediato en PowerShell

Abre PowerShell en esta carpeta. Docker Desktop y los tres servicios quedaron arrancados. El analizador CLI es un contenedor efímero que termina al guardar los resultados.

```powershell
./scripts/lab.ps1 queue
./scripts/lab.ps1 analyze
./scripts/lab.ps1 test
./scripts/lab.ps1 logs
./scripts/lab.ps1 stop   # conserva modelos, buzones y cola HOLD
./scripts/lab.ps1 start
```

Si tu política de PowerShell impide ejecutar scripts, usa los comandos Docker completos de abajo; no necesitas cambiar la política del sistema.

También puedes usar `.\scripts\lab.cmd status`, `start`, `analyze`, `test`, `queue`, `logs` o `stop`. Este lanzador ejecuta PowerShell con una política limitada a ese proceso; no modifica la política de Windows. Para CPU: `.\scripts\lab.cmd start -Cpu`.

## Revisión de funcionamiento del 26/10/2026

Consulta [REVISION_COMPLETA.md](REVISION_COMPLETA.md) para la comparación detallada con los requisitos, correcciones y límites. Las evidencias nuevas están en `results/review-*`; las anteriores se conservan como historial.

- 18 tests pasan en el host y en la imagen Docker actualizada.
- SMTP 465 con SSL/TLS e IMAP 1993 con SSL/TLS comprobados entre ambas cuentas. Los dos correos legítimos llegan una vez; los dos enlaces engañosos quedan en HOLD y ausentes de INBOX. Dos regresiones adicionales con mensajes cortos y saltos de línea también llegan una vez.
- La caída deliberada del Milter retiene un mensaje real en HOLD; el filtro se reinicia al terminar. Los seis mensajes que ya estaban retenidos se conservaron al recrear el servidor.
- Nueva evaluación `.eml`: seis inferencias locales, cinco respuestas IA válidas y una abstención por evidencia inválida. La política permitió tres y retuvo tres; no confundir esta ejecución con `results/final/`, que es anterior.
- Thunderbird: ambas cuentas usan `127.0.0.1`, IMAP 1993 y SMTP 465, SSL/TLS y contraseña normal. Se ha asociado cada identidad con su SMTP y guardado la huella del certificado actual solo para esos dos puertos. Copia previa en el perfil de Thunderbird. La interfaz confirma las dos cuentas, modo con conexión y mensajes recibidos. La prueba con el botón Enviar quedó pendiente porque Computer Use detectó actividad del usuario en la ventana y bloqueó las acciones.
- Se corrigió una configuración residual de Postfix que impedía el retorno interno de Amavis. El mensaje legítimo diferido se reintentó y fue entregado. Las cuarentenas no se liberaron en bloque.

Al arrancar, el Milter intenta precargar Qwen3 antes de abrir su puerto; el modelo queda residente durante 24 h. Un fallo de precarga no convierte un correo en seguro: el análisis fallido se retiene para revisión. `AI_TIMEOUT` ahora incluye las consultas de metadatos además de la inferencia, para no sumar tiempos de espera independientes al presupuesto SMTP.

### Arranque y análisis .eml

```powershell
docker desktop start
docker info
docker run --rm hello-world
# Opcional: copia .env.example a .env si deseas cambiar parámetros.
docker compose -f compose.yaml -f compose.gpu.yaml up -d ollama
docker compose exec -T ollama ollama pull qwen3:4b
docker compose build analyzer
docker compose -f compose.yaml -f compose.gpu.yaml run --rm analyzer python -m antiphishing samples/03_phishing.eml --output results/manual
docker compose -f compose.yaml -f compose.gpu.yaml run --rm analyzer python -m antiphishing --batch samples --output results/manual
docker compose -f compose.yaml -f compose.gpu.yaml run --rm analyzer python -m unittest discover -s tests -v
```

Para analizar otro archivo, cópialo a `samples/` y pasa su ruta `/app/samples/nombre.eml`. El volumen de entrada es de solo lectura. Los resultados pueden contener fragmentos de correo: trátalos como datos privados y no abras HTML recibido en un navegador.

**CPU:** omite `-f compose.gpu.yaml`, o usa `./scripts/lab.ps1 start -Cpu`. La ruta CPU está configurada pero la evaluación real de este equipo se hizo con GPU. En CPU puede ser necesario aumentar `AI_TIMEOUT` para CLI. El Milter mantiene un límite más corto; si la inferencia no termina, retiene para revisión. No cambiaremos WSL, drivers ni recursos del sistema automáticamente.

## Configuración comprobada

- Windows real, Ryzen 7 5700X, unos 32 GiB de RAM física y RTX 5070 de 12 GiB.
- Docker Desktop Linux/WSL2, motor 29.8.2; Docker ve 16 CPU lógicos y 16.722.583.552 bytes de RAM (15,57 GiB).
- GPU verificada con `docker run --rm --gpus all ubuntu:24.04 nvidia-smi`.
- Ollama 0.40.11; `qwen3:4b`, digest `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`, Q4_K_M, descarga de unos 2,5 GB. `ollama ps` confirmó 100% GPU y contexto 8192; tamaño cargado aproximado 3,9 GB.
- Imágenes Ollama, Python y docker-mailserver fijadas por digest en Compose/Dockerfile. El modelo es configurable; su digest real se registra en cada análisis. Si cambia el tag remoto, compara ese digest antes de comparar resultados.
- No hay dependencias Python externas: biblioteca estándar de Python 3.12. El Python del runtime de Codex sirvió para las pruebas del host; Docker evita que tengas que instalar Python.

Qwen3 es un modelo generalista preentrenado, **no un detector especializado de phishing validado**. No se entrena ni se invoca IA externa. `OLLAMA_NO_CLOUD=1`, validación de endpoint local, ningún tool call y ningún acceso al socket Docker. Ollama está publicado solo en `127.0.0.1:11434`. La red de Compose permite la descarga inicial y las consultas de reputación explícitas; no constituye aislamiento frente a código arbitrario.

## Funcionamiento y límites

`parser.py` procesa MIME/codificaciones, cabeceras, texto y HTML; conserva `href` y texto visible. No duplica alternativas idénticas; si el HTML tiene contenido distinto se conserva por separado. Marca discrepancia de host solo si el texto visible parece una URL o dominio: “pulsa aquí” no es discrepancia. No considera diferencias de ruta en el mismo host una discrepancia de dominio. No resuelve DNS, no visita enlaces ni abre adjuntos.

Límites: mensaje 10 MiB, adjunto decodificado 2 MiB, texto/HTML 12.000 caracteres, 100 URLs, entrada serializada al modelo 16.000 caracteres y salida 700 tokens. Se registra `incomplete` si se supera un límite; los adjuntos omitidos no reciben un hash ficticio. Un mensaje superior al límite no se parsea parcialmente. MIME anidado como adjunto se marca incompleto. HTML se interpreta de forma estática, sin CSS/JavaScript ni semántica visual de navegador. No descomprime ZIP ni demuestra ausencia de malware.

`ai.py` solicita JSON por esquema, valida tipos, estados, límites y citas literales; una evidencia inventada invalida la respuesta. Conserva `raw_model_response` para auditoría. El correo se presenta como dato no fiable, incluidas las órdenes de prompt injection. Esto reduce el riesgo, pero no demuestra inmunidad a inyecciones. No se produce una probabilidad calibrada.

`policy.py`, versión `academic-v1`, decide por este orden:

1. Discrepancia de host o reputación con detección: cuarentena.
2. IA válida clasifica sospechoso: cuarentena.
3. Análisis incompleto, IA no disponible/indeterminada o reputación activada que falla: pendiente de revisión.
4. Sin señales suficientes: permitir; **no significa seguro**.

Señales estáticas, IA y reputación se guardan por separado. La decisión CLI solo informa; **el comando `.eml` por sí solo no intercepta correo**. El Milter sí intercepta el servidor y retiene tanto cuarentena como pendiente de revisión.

## Reputación: desactivada por defecto

`disabled_demo` significa que no se consultó nada; no son resultados limpios ni respuestas inventadas. No se han probado peticiones reales a proveedores porque no se proporcionaron claves ni se activó su uso.

- `REPUTATION_HASHES=1` y `VT_API_KEY`: consulta GET del informe de un SHA-256 en VirusTotal. Solo sale la huella; nunca se suben bytes del adjunto.
- `REPUTATION_URLS=1`: consulta informes URL existentes en VirusTotal y Google Safe Browsing v5 `urls:search`; salen las URLs completas, incluidos posibles identificadores/tokens privados. Requiere `VT_API_KEY` y `GSB_API_KEY`. Un proveedor sin clave queda no disponible. No se solicita un nuevo escaneo.
- Safe Browsing consulta amenazas de URLs, **no hashes de archivos**. v4 está deprecada; se utiliza v5. Confirma acceso y cuotas en tu proyecto de Google antes de activarlo. Uso no comercial; las advertencias son “posible amenaza”, con atribución a Google. Puede haber falsos positivos y negativos: https://safebrowsing.google.com/ .
- Hash desconocido (`404`) = `unknown`; informe sin detecciones = `no_known_detection`, ninguno garantiza seguridad. Errores, 429 o JSON inválido = `unavailable`.
- Caché SQLite persistente: claves de caché con hash, TTL VT de una hora/300 s desconocidos y TTL Google limitado por `cacheDuration`. Reserva de cuota compartida: VT una petición cada 16 s; Google una por segundo; 429 activa enfriamiento de 60 s. Máximo dos intentos por fallo de red, timeout de 10 s; no se reintentan errores HTTP. La cuota real depende de tu cuenta; el límite local no garantiza respetar cuotas consumidas por otras aplicaciones.
- Claves en `.env` excluido de Git; nunca en código ni resultados. **El Milter conserva reputación desactivada** para mantener acotado el tiempo SMTP; la activación de `.env` afecta al analizador CLI. Una futura reputación en servidor necesita cola de trabajo asíncrona y presupuesto de consultas.

## Servidor de correo y cuarentena real

```powershell
docker compose -f compose.yaml -f compose.gpu.yaml -f compose.mail.yaml up -d ollama milter mailserver
docker compose -f compose.yaml -f compose.gpu.yaml -f compose.mail.yaml exec -T mailserver postqueue -p
docker compose -f compose.yaml -f compose.gpu.yaml -f compose.mail.yaml logs --tail 80 mailserver milter
docker compose -f compose.yaml -f compose.gpu.yaml -f compose.mail.yaml stop
```

Dominio `empresa.lab`, hostname `mail.empresa.lab`. Cuentas `docente@empresa.lab` y `alumno@empresa.lab`; contraseñas aleatorias locales en `mail-config/credentials.json`, excluido de Git. No se imprimen aquí ni en registros de prueba.

Cliente: servidor `127.0.0.1` (o `localhost`), SMTP seguro directo 465 con SSL/TLS/autenticación, SMTP submission 1587 con STARTTLS/autenticación, IMAP 1993 con TLS (o 1143 con STARTTLS). SMTP entrante 2525. Todos los puertos publicados se enlazan únicamente a loopback IPv4/IPv6. El certificado local incluye localhost, mail.empresa.lab, 127.0.0.1 y ::1; es un certificado de servidor con CA:false y serverAuth. Las pruebas confían explícitamente en `mail-config/cert.pem`, sin desactivar la verificación TLS. No se ha modificado el almacén de certificados de Windows. Certificado válido 365 días desde la creación.

`scripts/setup_mail.py` crea cuentas y certificado de laboratorio sin sobrescribirlos; para una instalación nueva requiere Python disponible (`python scripts/setup_mail.py`). También copia `scripts/enable-milter.sh` a `mail-config/user-patches.sh` si no existe, antes de arrancar el servidor. En este equipo ya está hecho. El script añade nuestro Milter conservando los milters existentes y se ejecuta al arrancar DMS. `mail-config` contiene secretos y configuración local y no está en Git; guarda una copia privada si necesitas recuperar la instalación.

El Milter usa el protocolo 6 de Postfix y solicita `quarantine` al final de DATA. El mensaje queda en HOLD dentro del volumen persistente `mail-state`; los JSON de `results/mail/` son auditoría, **no la cuarentena**. No hay copia `.eml` presentada como interceptación ni un circuito de reinyección propio. Amavis conserva su transporte interno habitual.

IA en servidor: timeout 25 s. Conexión Milter: 5 s; comandos/contenido: 40 s. Un filtro ausente o fallido usa `milter_default_action=quarantine`, de modo que no se entrega por defecto. Un error al escribir auditoría devuelve fallo temporal SMTP para que el remitente reintente. La carga inicial del modelo puede superar el presupuesto; precárgalo ejecutando el análisis CLI. Servidor Milter serial con cola pequeña, apropiado para este laboratorio; para producción se necesita trabajo asíncrono, control de concurrencia y pruebas de carga. Los otros controles SMTP también añaden latencia: 40 s no es una garantía de duración total de la conexión.

No hay liberación automática. Inspecciona un ID concreto con `postcat -q ID`. Tras una revisión humana, el administrador puede liberar **solo ese ID** con `postsuper -H ID`; no se incluye liberación masiva ni se ejecutó ninguna. Una liberación HOLD no vuelve a pasar por nuestro Milter. No se ha implementado UI de revisión ni protección contra duplicados enviados de nuevo por el cliente: SMTP puede duplicar tras una pérdida del acuse. Sí se comprobó una única entrega del correo legítimo y que nuestro filtro no reinyecta ni forma bucles.

Rspamd, Amavis y los controles de autenticación configurados por DMS se conservaron. ClamAV y Fail2Ban están explícitamente desactivados en este laboratorio de muestras inocuas y puertos locales, para no añadir consumo y privilegios; no se afirma protección antivirus completa. DMS advierte de controles SPF/DMARC redundantes al combinar sus valores predeterminados con Rspamd; no se desactivaron para hacer pasar pruebas. SPF/DKIM/DMARC reales del dominio de Internet no se han validado para `empresa.lab`.

## Pruebas y evidencias

- `results/docker-tests-final.txt`: pruebas automatizadas; los mocks están identificados en sus nombres y solo prueban contrato/fallos. No son inferencias reales.
- `results/final/*.json` y `summary.csv`: evaluación real del conjunto final, con clasificación observada, decisión, motivos, tiempos, estado de IA/reputación, versión y digest del modelo y configuración.
- `results/real/` y `real-audited/`: ejecuciones anteriores conservadas; usaban el conjunto inicial. No mezclarlas con la evaluación final. Los hashes permiten distinguir entradas.
- `results/mail-baseline.json`: entrega SMTP/IMAP normal antes de activar el filtro.
- `results/mail-filtered.json`: legítimo recibido una vez, enlace engañoso ausente de INBOX.
- `results/postfix-queue*.jsonl`: cola HOLD y persistencia; `results/mail/*.json`: motivos y queue ID.
- `results/mail-outage.json`: filtro detenido deliberadamente, correo legítimo retenido en lugar de entregado.
- `results/relay-check.txt`: rechazo de destinatario externo sin autenticación.
- `results/relay-port25.txt`: `554 Relay access denied` en SMTP entrante, además de submission.
- `results/gpu-inference.txt`: uso real de GPU; `results/environment.txt` y logs de Docker: versiones/estado.

Las seis muestras son sintéticas, inocuas y usan `.example`; `empresa.lab` se limita al dominio local solicitado. Etiquetas esperadas en `samples/expected.json`, nunca enviadas al modelo. No se calculan métricas de eficacia general. Un indeterminado es una abstención de la IA: no se cuenta como acierto ni se transforma en “seguro”. La política puede retenerlo por señales estáticas, por lo que la clasificación IA y la decisión deben evaluarse por separado. La muestra es demasiado pequeña para demostrar sensibilidad, precisión o resistencia a ataques reales.

La primera prueba del servidor fue rechazada por Amavis al faltar Date en los mensajes generados. Se corrigieron las muestras manteniendo los controles. La validación estricta también detectó evidencias inventadas por el modelo; se conservan los resultados originales y no se sustituyen por etiquetas esperadas.

La evaluación final observada permitió tres mensajes y retuvo tres, con seis respuestas IA válidas. La carga inicial tardó unos 57 s; las siguientes inferencias, 0,6–1,8 s. La validación de citas no valida la veracidad de todos los motivos: por ejemplo, el modelo afirmó incorrectamente que `enti.example` no era un dominio reservado. Sus explicaciones requieren revisión humana aunque la clasificación coincida con la etiqueta esperada. En la primera prueba de caída, el reinicio interrumpió la comprobación auxiliar de relay después de comprobar la ausencia en INBOX; se repitió sin ese solapamiento (`mail-outage-final.log`).

## Fuentes oficiales consultadas

- [Ollama Docker](https://docs.ollama.com/docker), [salida estructurada](https://docs.ollama.com/capabilities/structured-outputs) y [Qwen3 4B](https://ollama.com/library/qwen3:4b).
- [VirusTotal: informe de archivo](https://docs.virustotal.com/reference/file-info) e [informe URL](https://docs.virustotal.com/reference/url-info).
- [Safe Browsing v5 urls.search](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search) y [restricciones de uso](https://developers.google.com/safe-browsing/v4/usage-limits).
- [DMS instalación](https://docker-mailserver.github.io/docker-mailserver/latest/examples/tutorials/basic-installation/), [variables](https://docker-mailserver.github.io/docker-mailserver/latest/config/environment/), [user-patches.sh](https://docker-mailserver.github.io/docker-mailserver/latest/faq/).
- [Postfix Milter, fuente del proyecto](https://github.com/vdukhovni/postfix/blob/master/postfix/html/MILTER_README.html), [filtro after-queue](https://www.postfix.org/FILTER_README.html). Se evaluó after-queue, pero se implementó Milter/HOLD para evitar una nueva reinyección en este prototipo.
