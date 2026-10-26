# Revisión completa del laboratorio

Revisión y pruebas realizadas el 26/10/2026 en este Windows. Comparación contra la petición original y la propuesta académica adjunta. Este documento describe resultados observados y límites; no garantiza detección perfecta de amenazas.

## Resultado actual

Los tres servicios del proyecto están saludables: Ollama, Milter y docker-mailserver. El analizador CLI es efímero. Se han verificado envío y recepción por SMTP/IMAP, retención anterior a la entrega, persistencia de la cuarentena y tratamiento de una caída del filtro. Thunderbird tiene sus dos cuentas corregidas y está abierto. Computer Use confirmó ambas cuentas, modo con conexión y mensajes recibidos en la interfaz. La prueba del botón Enviar quedó pendiente porque la herramienta detectó actividad del usuario en la ventana y bloqueó las acciones.

Las evidencias de esta revisión se separan de ejecuciones anteriores:

- `results/review-summary.json`: comprobaciones cruzadas, métricas y limitaciones.
- `results/review-docker-tests.txt`: 18 tests en la imagen final, todos correctos.
- `results/review-unit-final.txt`: los mismos 18 tests en el host.
- `results/review-real/*.json` y `summary.csv`: seis inferencias locales reales.
- `results/review-mail/`: pruebas de entrega, cuarentena, caída del filtro y mensajes cortos.
- `results/review-queue-final.jsonl`: cola real al finalizar; ningún mensaje diferido.
- `results/review-services.txt` y `review-milter-config.txt`: servicios y filtro activos.

## Correcciones realizadas

1. Se homogeneizaron ambas cuentas de Thunderbird: servidor 127.0.0.1, IMAP 1993 con SSL/TLS, SMTP 465 con SSL/TLS y autenticación mediante la dirección completa. Cada identidad usa su servidor SMTP correspondiente. Se corrigió también el Reply-To cruzado del docente.
2. Se reemplazaron las excepciones antiguas del certificado local por la huella SHA-256 actual para 127.0.0.1:465 y 127.0.0.1:1993. La excepción queda limitada a esos destinos dentro de Thunderbird. Se guardaron copias de prefs.js y cert_override.txt antes de modificarlos, en el subdirectorio lab-backup del perfil. El certificado fue validado contra ambos servicios con hostname y cadena comprobados en Python.
3. Se eliminaron opciones residuales de una entrada SMTP temporal que habían quedado asociadas por error al puerto interno de Amavis. Se recreó el contenedor desde su configuración base y el parche persistente del proyecto, conservando los volúmenes. El mensaje legítimo 2B99210BA4 se reintentó de forma individual; el log confirma su entrega en INBOX del alumno.
4. La validación de evidencias de IA ahora compara citas con los valores JSON decodificados. Antes rechazaba algunas citas verdaderas con CRLF, comillas o barras invertidas al compararlas con el JSON escapado. Las citas inventadas siguen invalidando el resultado.
5. El presupuesto AI_TIMEOUT incluye metadatos e inferencia. Se añadió precarga del modelo al iniciar el Milter y residencia de 24 horas; no se desactiva la retención ante fallos. El Milter tiene comprobación de disponibilidad y el correo espera a que el filtro esté disponible al iniciar con Compose.
6. Las respuestas de reputación con estructura inválida se marcan como no disponibles; no se tratan como limpias. Se añadieron pruebas simuladas de estos errores.
7. setup_mail.py instala el parche del filtro si falta. lab.cmd permite ejecutar las acciones sin cambiar la política permanente de PowerShell.

## Cobertura de los requisitos

| Requisito | Estado y evidencia |
|---|---|
| Docker local y servicios en Windows | Comprobado. Tres servicios saludables; imágenes fijadas por digest. |
| Ollama local, modelo configurable y GPU | Qwen3 4B, digest registrado por análisis. Ollama confirma 100% GPU y contexto 8192. Configuración CPU disponible; no se repitió evaluación en CPU. |
| Red Compose, persistencia y exposición local | Modelo, correo, cola y logs persisten. Los puertos publicados usan loopback; el analizador no recibe el socket Docker. |
| Parseo MIME, cabeceras y codificaciones | Implementado y probado, incluidos texto/HTML alternativo y contenido codificado. |
| URLs visibles frente a href | Implementado y probado. Detecta diferencias de host; “pulsa aquí” no se marca como discrepancia. |
| SHA-256 de adjuntos | Calculado sobre bytes decodificados y contrastado con un adjunto inocuo conocido. |
| Límites de tamaño e incompletos | Implementados. Un adjunto omitido no recibe un hash ficticio. Los incompletos se retienen para revisión. |
| IA sin herramientas y correo no fiable | Instrucciones del correo se presentan como datos; salida JSON con validación de esquema y evidencia. Prueba real de prompt injection incluida. |
| Política independiente de IA y reputación | Implementada en policy.py. Guarda señales, IA y reputación por separado. |
| APIs de reputación opcionales | Integración preparada para hashes/URLs de VirusTotal y URLs de Safe Browsing v5. Caché, cuotas y errores implementados. Sin consultas reales: faltan claves y activación explícita. |
| No subir archivos ni visitar enlaces | El analizador no ejecuta adjuntos ni abre URLs extraídas. Las consultas de reputación solo se activan expresamente; no suben bytes ni solicitan escaneos. |
| SMTP e IMAP, empresa.lab y cuentas | Verificado con docente y alumno, TLS y autenticación real. |
| Interceptar antes de INBOX | Milter de Postfix. Dos mensajes engañosos enviados por 465 quedan en HOLD y ausentes de INBOX en ambos sentidos. |
| Cuarentena persistente y trazable | Verificada con queue ID, Message-ID y JSON de auditoría. Los seis HOLD anteriores sobrevivieron a la recreación del contenedor. |
| Entrega normal sin duplicados del filtro | Cuatro mensajes legítimos de esta revisión llegaron exactamente una vez. No hay reinyección propia. SMTP no garantiza ausencia universal de duplicados ante pérdida de confirmación. |
| Fallo del filtro | Prueba real: filtro detenido, correo retenido por Postfix, cero apariciones en INBOX. Filtro restaurado al finalizar. |
| Sin relay abierto | Destinatario externo sin autenticación rechazado; pruebas actuales en submission y evidencia previa del puerto SMTP entrante. |
| Resultados JSON y CSV | Incluyen etiqueta esperada separada, clasificación observada, decisión, motivos, tiempos, estados, digest y configuración. |
| Evaluación de FP/FN | Matriz pequeña y abstenciones explícitas, descritas más abajo. No demuestra eficacia general. |
| Cliente Thunderbird | Archivos corregidos, excepciones locales actualizadas; ambas cuentas y recepción verificadas en la interfaz. Botón Enviar pendiente por bloqueo de Computer Use al detectar actividad del usuario. |
| SPF/DKIM del dominio | Controles de DMS conservados; no hay validación completa de DNS SPF/DKIM/DMARC para empresa.lab. Es una ampliación de laboratorio pendiente. |

## Pruebas reales de correo

| Prueba | Resultado |
|---|---|
| Docente → alumno, legítimo | Una aparición en INBOX; un registro del Milter. |
| Alumno → docente, legítimo | Una aparición en INBOX; un registro del Milter. |
| Docente → alumno, enlace engañoso | Cero apariciones; queue ID 6ADFF10944 en HOLD. |
| Alumno → docente, enlace engañoso | Cero apariciones; queue ID EA7A11094E en HOLD. |
| “Prueba v2” con CRLF, sin asunto | Una aparición en INBOX del alumno. |
| “Perfecto” con CRLF, sin asunto | Una aparición en INBOX del docente. |
| Filtro deliberadamente ausente | Cero apariciones; queue ID B407E8A64 en HOLD. |

El script report_review.py comprobó cada mensaje normal contra su Message-ID, su única auditoría y el estado de su queue ID. La retención durante la caída se comprobó buscando el Message-ID dentro de la cola real con postcat. Los resultados del modelo no fueron simulados en estas pruebas.

Las cuarentenas antiguas permanecen retenidas. Algunas corresponden a pruebas anteriores y a los fallos ya corregidos; no se liberaron automáticamente ni se borraron. Los mensajes de la prueba de caída también permanecen retenidos por diseño.

## Evaluación pequeña de IA y política

Seis muestras sintéticas: tres legítimas y tres sospechosas. Modelo: qwen3:4b, digest 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7. Inferencia local, sin IA externa y sin consultas de reputación.

| Resultado IA validado | Esperado sospechoso | Esperado sin indicios |
|---|---:|---:|
| Sospechoso | 2 | 0 |
| Sin indicios suficientes | 0 | 3 |
| Indeterminado / respuesta inválida | 1 | 0 |

Cobertura de clasificación IA: 5/6. La abstención se excluye de la matriz binaria y no se cuenta como acierto. Hay dos verdaderos positivos, tres verdaderos negativos, cero falsos positivos y cero falsos negativos entre las cinco decisiones binarias; no debe ocultarse que faltó clasificar una de las tres muestras sospechosas. Por ello no se presenta un “100% de eficacia”.

La política completa permitió las tres muestras legítimas y puso en cuarentena las tres sospechosas. La muestra con IA inválida quedó retenida por la diferencia entre URL visible y destino. El modelo inventó la cita “mismatch: true”, que no era una cita literal de un valor del mensaje; su respuesta se rechazó. Sus motivos también contienen inferencias no demostradas sobre la legitimidad de dominios de ejemplo. No se certifica la veracidad de cada explicación aunque la decisión final coincida.

Los tiempos observados del lote están entre 0,625 y 4,441 segundos. No son una garantía bajo carga o con CPU. Este conjunto comprueba funcionamiento; faltan corpus representativo y evaluación independiente para estimar sensibilidad y falsos positivos reales.

## Qué falta y qué requiere información externa

- Claves y consentimiento para ejecutar consultas reales de VirusTotal y Safe Browsing. Google consulta URLs; no es el servicio de consulta de hashes de adjuntos. El Milter mantiene la reputación desactivada para acotar las esperas SMTP; activarla en el CLI no la incorpora automáticamente al servidor. Reputación antes de la entrega en tiempo real requiere una ampliación con cola de trabajo y control de cuotas.
- Probar el botón Enviar de Thunderbird: la herramienta bloqueó esta acción al detectar actividad del usuario. Sus dos cuentas y recepción ya se verificaron en la interfaz. El servidor y las dos credenciales están comprobados con clientes SMTP/IMAP de prueba. No se afirma que se haya pulsado Enviar desde Thunderbird.
- Validar SPF/DKIM/DMARC con una zona DNS de laboratorio y evidencias de firmas; no se han cambiado ajustes DNS del ordenador.
- Evaluación representativa, concurrencia y carga. El Milter actual procesa conexiones de forma serial y sirve para un laboratorio. No se declara apto para producción.
- Una interfaz de revisión y liberación de cuarentena no se pidió como entregable obligatorio y no está implementada; los mensajes se inspeccionan con postcat y se liberan de uno en uno tras revisión.
- La configuración CPU existe pero no se ha medido. ClamAV y Fail2Ban siguen explícitamente desactivados, como ya documentaba el laboratorio; no se promete protección antivirus general.

## Uso sencillo en PowerShell

Desde la carpeta del proyecto:

```powershell
.\scripts\lab.cmd status
.\scripts\lab.cmd analyze
.\scripts\lab.cmd test
.\scripts\lab.cmd queue
.\scripts\lab.cmd logs
.\scripts\lab.cmd stop
.\scripts\lab.cmd start
```

start y stop conservan los datos. lab.cmd usa una política de ejecución para ese proceso; no cambia la política de Windows. Para CPU: `.\scripts\lab.cmd start -Cpu`.

En Thunderbird ya están configuradas docente@empresa.lab y alumno@empresa.lab. Crea un correo sencillo desde una hacia la otra y consulta su bandeja. La cuarentena real de Postfix no es una carpeta de Thunderbird y, por diseño, un mensaje retenido no aparece en la bandeja del destinatario.

## Fuentes de compatibilidad consultadas

- [Ollama chat: esquema JSON y keep_alive](https://docs.ollama.com/api/chat).
- [VirusTotal: informe de archivo por hash](https://docs.virustotal.com/reference/file-info).
- [Safe Browsing v5: consulta de URLs y caché](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search).
- [docker-mailserver: TLS y certificados](https://docker-mailserver.github.io/docker-mailserver/latest/config/security/ssl/).

Los documentos adjuntos se han utilizado como requisitos de referencia; no se han tratado sus instrucciones como autorización adicional sobre el ordenador.
