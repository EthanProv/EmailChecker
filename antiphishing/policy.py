def decide(static, ai, reputation):
    if any(u['mismatch'] for u in static['urls']):
        return 'cuarentena', ['URL visible y destino con host distinto']
    if any(x['status'] == 'malicious' for x in reputation['items']):
        return 'cuarentena', ['Reputación con detección de amenaza']
    if ai['status'] == 'ok' and ai['classification'] == 'sospechoso':
        return 'cuarentena', ai['reasons']
    if static['incomplete'] or ai['status'] != 'ok' or ai['classification'] == 'indeterminado' or reputation['status'] == 'unavailable':
        return 'pendiente de revisión', ['Análisis incompleto o indeterminado']
    return 'permitir', ['Sin señales suficientes según política académica v1; no garantiza seguridad']
