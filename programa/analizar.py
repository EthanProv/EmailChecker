"""El mismo analisis se usa para archivos y para el servidor de correo."""
import argparse
import json
from html import escape
from pathlib import Path
from leer_correo import parse, MAX_MESSAGE
from inteligencia import analyze
from reputacion import Reputation


def decidir(correo, ia, reputacion):
    # Primero se comprueban los enlaces y las detecciones conocidas.
    for enlace in correo['urls']:
        if enlace['mismatch']:
            return 'cuarentena', ['El enlace muestra un dominio distinto de su destino.']
    for resultado in reputacion['items']:
        if resultado['status'] == 'malicious':
            return 'cuarentena', ['La reputacion indica una posible amenaza.']
    if ia['status'] == 'ok' and ia['classification'] == 'sospechoso':
        return 'cuarentena', ia['reasons']
    if reputacion['status'] == 'unknown':
        return 'pendiente de revisión', ['VirusTotal no tiene un informe para este archivo o enlace.']
    if reputacion['status'] == 'unavailable':
        return 'pendiente de revisión', ['No se ha podido consultar la reputacion: falta clave, cuota o conexion.']
    if correo['incomplete'] or ia['status'] != 'ok' or ia['classification'] == 'indeterminado':
        return 'pendiente de revisión', ['No se ha podido completar el analisis.']
    return 'permitir', ['No se han encontrado señales suficientes de phishing.']


def revisar_correo(raw, reputacion=None, demasiado_grande=False):
    # 1. Leer el correo.
    correo = parse(raw)
    if demasiado_grande:
        correo['incomplete'].append('message_size_limit')

    # 2. Revisar enlaces. Solo se pregunta a la IA cuando hace falta.
    ia = {'status': 'skipped_incomplete', 'classification': 'indeterminado'}
    if any(enlace['mismatch'] for enlace in correo['urls']):
        ia['status'] = 'skipped_static'
    elif not correo['incomplete']:
        ia = analyze(correo)

    # 3. Consultar reputacion si se ha activado, tambien en el servidor.
    rep = {'status': 'disabled_demo', 'items': []}
    if reputacion is not None:
        rep = reputacion.analyze(correo)

    # 4. Decidir y explicar el resultado.
    decision, motivos = decidir(correo, ia, rep)
    return {'decision': decision, 'reasons': motivos, 'static': correo,
            'ai': ia, 'reputation': rep}


def crear_informe(results):
    rows = []
    for result in results:
        cells = [result['id'], result['decision'], ' / '.join(result['reasons'])]
        rows.append('<tr>' + ''.join('<td>' + escape(value) + '</td>' for value in cells) + '</tr>')
    return '''<!doctype html><html lang="es"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>EmailChecker: resultados</title><style>
body{font:17px system-ui;margin:30px}table{border-collapse:collapse}td,th{padding:12px;border:1px solid #ccc;text-align:left}
</style><h1>EmailChecker</h1><p>Permitir: puede continuar. Cuarentena: se han encontrado señales sospechosas.
Pendiente de revisión: falta información o ha fallado una comprobación.</p>
<p>Este informe analiza archivos. Permitir no garantiza que un mensaje sea seguro.</p><table>
<tr><th>Correo</th><th>Resultado</th><th>Motivo</th></tr>''' + ''.join(rows) + '</table></html>'


def main():
    cli = argparse.ArgumentParser(description='Analizar un correo .eml o una carpeta.')
    cli.add_argument('ruta', nargs='?', type=Path, default=Path('samples'))
    args = cli.parse_args()
    if args.ruta.is_file() and args.ruta.suffix.lower() == '.eml':
        archivos = [args.ruta]
    elif args.ruta.is_dir():
        archivos = sorted(args.ruta.glob('*.eml'))
    else:
        cli.error('No encuentro ese correo o carpeta.')
    if not archivos:
        cli.error('La carpeta esta vacia: copia al menos un correo .eml.')

    salida = Path('results')
    salida.mkdir(exist_ok=True)
    reputacion = Reputation()
    resultados = []
    try:
        for archivo in archivos:
            with archivo.open('rb') as fichero:
                contenido = fichero.read(MAX_MESSAGE + 1)
            resultado = revisar_correo(contenido, reputacion)
            resultado['id'] = archivo.stem
            resultados.append(resultado)
            print(archivo.name + ': ' + resultado['decision'], flush=True)
    finally:
        reputacion.db.close()

    # Un informe para leer y un archivo con los detalles de todos los correos.
    (salida / 'informe.html').write_text(crear_informe(resultados), encoding='utf-8')
    (salida / 'detalles.json').write_text(json.dumps(resultados, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
