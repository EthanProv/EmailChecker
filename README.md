# EmailChecker

Abre **EmailChecker.cmd** con doble clic. Docker Desktop debe estar instalado.

- **1. Iniciar**: arranca el correo y la IA.
- **2. Probar**: comprueba el programa con correos de prueba.
- **3. Analizar archivos**: revisa los correos .eml de datos/ejemplos.
- **4. Ver informe**: abre el resultado del analisis.
- **5. Ver cuarentena**: muestra los correos retenidos.
- **6. Detener**: para el servidor conservando tus correos.
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

VirusTotal y Google siguen siendo opcionales y estan desactivados por defecto.
Sus opciones estan en programa/.env.example; se configuran copiandolo a programa/.env.
Solo se usan al analizar archivos. Consultan hashes o URLs; no suben adjuntos.
Los detalles de errores se guardan en datos/resultados/operaciones.log.
La opcion Probar guarda ahi su resultado, sin crear mas archivos de informes.

Para un equipo sin GPU NVIDIA puedes ejecutar EmailChecker.cmd start -Cpu.
