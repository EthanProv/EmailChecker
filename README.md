# EmailChecker

Descomprime el proyecto en una carpeta propia y abre **EmailChecker.cmd** con doble clic.
La primera vez instala Docker Desktop y Thunderbird si faltan, prepara WSL 2,
descarga la IA y configura las dos cuentas de correo automaticamente.
Necesitas Internet, Windows 10/11 actualizado de 64 bits (x64), al menos 8 GB de RAM
y virtualizacion activada. Windows puede pedir permiso de administrador o un reinicio:
despues vuelve a abrir EmailChecker.cmd. Si falta App Installer, el programa indica
que debes instalarlo desde Microsoft Store. La primera descarga puede tardar bastante.

Las contrasenas del laboratorio se generan automaticamente y Thunderbird las guarda
cifradas. Solo tienes que aportar tu propia API de VirusTotal si quieres activarlo;
puedes saltarte ese paso y configurarla despues. No necesitas una cuenta de Gmail.
Se crea un perfil separado de Thunderbird dentro de datos/thunderbird.
Tus perfiles personales de Thunderbird se conservan.

- **1. Iniciar**: arranca el correo y la IA.
- **2. Probar**: comprueba el programa con correos de prueba.
- **3. Analizar archivos**: revisa los correos .eml de datos/ejemplos.
- **4. Ver informe**: abre el resultado del analisis.
- **5. Ver cuarentena**: muestra los correos retenidos.
- **6. Detener**: para el servidor conservando tus correos.
- **7. Configurar VirusTotal**: pide tu clave API sin mostrarla y permite elegir si tambien consultas enlaces.
- **8. Abrir Thunderbird**: arranca el laboratorio y abre sus cuentas de correo.
- **0. Salir**: cierra el menu. El servidor sigue funcionando.

## Las dos carpetas

**programa** contiene el codigo y la configuracion de Docker.
Para entender el analisis, abre programa/analizar.py y lee revisar_correo:
leer el correo, revisar enlaces, consultar la IA y decidir.
El servidor usa esa misma funcion.

**datos** contiene lo que usas y lo que guarda el programa:

- ejemplos: correos .eml que puedes analizar.
- resultados/informe.html: informe para leer en el navegador.
- resultados/detalles.json: detalles de ese mismo analisis.
- resultados/correos: registro de los mensajes filtrados por el servidor.
- cuentas: contrasenas y certificado de esta instalacion. Es privada.
- thunderbird: perfil privado con las dos cuentas del laboratorio.
- respaldo: copias recuperables de las versiones anteriores.

## Correo en Thunderbird

Cuentas: docente@empresa.lab y alumno@empresa.lab.
Servidor: 127.0.0.1. Entrada IMAP: 1993 con SSL/TLS.
Salida SMTP: 465 con SSL/TLS. Usuario: el correo completo.
Autenticacion: contrasena normal. Contrasenas: datos/cuentas/credentials.json.

Los correos enviados al servidor se analizan automaticamente.
Si son sospechosos o falla el analisis, quedan retenidos en la cuarentena de Docker.
El analisis de archivos crea el informe; no libera correos.

La IA trabaja en tu ordenador. El programa no abre enlaces ni ejecuta adjuntos.
Permitir significa que no se encontraron señales suficientes, no que sea seguro.

VirusTotal funciona tanto con archivos como con los correos enviados desde Thunderbird.
Para activarlo, elige **7** y pega tu clave API. Se guarda en programa/.env, excluido de Git.
Se consultan los hashes de los adjuntos; no se suben los archivos.
El menu pide permiso aparte para consultar los enlaces completos.
Si detecta una amenaza, retiene el correo. Si el hash es desconocido o falla la consulta,
lo deja pendiente de revision. Sin adjuntos, siguen actuando las reglas y la IA.
Las respuestas se guardan durante una hora (cinco minutos si el archivo es desconocido).
Las consultas externas tienen un presupuesto de ocho segundos por mensaje y limite de peticiones.
Con muchas consultas nuevas puede agotarse la cuota y quedar correo pendiente de revision.
Es un laboratorio de pocos mensajes; no hay una cola de consultas en segundo plano.

Los enlaces solo se consultan si activas REPUTATION_URLS=1 en programa/.env:
esto envia la URL completa a VirusTotal. Google es opcional para el analizador de archivos
si tambien configuras GSB_API_KEY. Las opciones estan en programa/.env.example.
Antes de activar VirusTotal, no se realizan consultas reales.
Los detalles de errores se guardan en datos/resultados/operaciones.log.
La opcion Probar guarda ahi su resultado, sin crear mas archivos de informes.

El instalador elige una IA pequena para CPU o una mayor para una GPU NVIDIA compatible.
En equipos modestos el analisis puede tardar mas; si no termina, el correo queda retenido.
Para forzar CPU puedes ejecutar EmailChecker.cmd start -Cpu.

## Compartir con un amigo

Comparte el paquete limpio **datos/resultados/EmailChecker.zip**. Tu amigo debe
descomprimirlo y abrir EmailChecker.cmd. Cada ordenador crea sus propias cuentas,
contrasenas y certificado. No compartas la carpeta datos/cuentas, datos/thunderbird
ni programa/.env: contienen informacion privada.

Para volver a crear el ZIP despues de cambiar el codigo:
`powershell -NoProfile -ExecutionPolicy Bypass -File programa/instalar.ps1 -Empaquetar`

Para repetir la configuracion automatica, cierra el Thunderbird del laboratorio
y ejecuta `EmailChecker.cmd install`.
