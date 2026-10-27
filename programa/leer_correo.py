import hashlib
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_MESSAGE = 10 * 1024 * 1024
MAX_ATTACHMENT = 2 * 1024 * 1024
MAX_TEXT = 12000
URL = re.compile(r'https?://[^\s<>"\x27]+', re.I)
DOMAIN = re.compile(r'^(?:https?://)?(?:[\w-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/\S*)?$', re.I)

def host(value):
    try:
        if '://' not in value:
            value = 'https://' + value
        name = urlsplit(value).hostname or ''
        return name.rstrip('.').encode('idna').decode().lower()
    except (ValueError, UnicodeError):
        return ''

class HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links = [], []
        self.active = None
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a':
            self.active = [dict(attrs).get('href', ''), '']

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.active is not None:
                self.active[1] += data

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.active is not None:
            href, visible = self.active
            visible = visible.strip()
            if href.lower().startswith(('http://', 'https://')):
                self.links.append({'href': href, 'visible': visible,
                                   'mismatch': bool(DOMAIN.fullmatch(visible) and host(visible) != host(href))})
            self.active = None

def parse(raw):
    """Leer cabeceras, texto, enlaces y hashes sin ejecutar el contenido."""
    result = {'headers': {}, 'text': '', 'html': '', 'urls': [], 'attachments': [], 'incomplete': []}
    if len(raw) > MAX_MESSAGE:
        result['incomplete'].append('message_size_limit')
        return result
    message = BytesParser(policy=policy.default).parsebytes(raw)
    result['headers'] = {k: str(message.get(k, '')) for k in ('Subject', 'From', 'Reply-To', 'Return-Path', 'Message-ID')}
    texts, htmls = [], []
    for part in message.walk():
        if part.defects:
            result['incomplete'].append('mime_defect')
        if part.is_multipart():
            if part.get_content_disposition() == 'attachment':
                result['incomplete'].append('nested_message_attachment')
            continue
        data = part.get_payload(decode=True) or b''
        if part.get_filename() or part.get_content_disposition() == 'attachment' or part.get_content_maintype() != 'text':
            item = {'name': part.get_filename(), 'size': len(data), 'sha256': None}
            if len(data) > MAX_ATTACHMENT:
                result['incomplete'].append('attachment_size_limit')
            else:
                item['sha256'] = hashlib.sha256(data).hexdigest()
            result['attachments'].append(item)
        elif part.get_content_type() in ('text/plain', 'text/html'):
            try:
                content = data.decode(part.get_content_charset() or 'utf-8', errors='strict')
            except (LookupError, UnicodeError):
                content = data.decode('utf-8', errors='replace')
                result['incomplete'].append('text_decode_fallback')
            if part.get_content_type() == 'text/html':
                htmls.append(content)
            else:
                texts.append(content)
    html = HTML()
    html.feed('\n'.join(htmls))
    plain = '\n'.join(texts)
    result['text'] = plain or ' '.join(html.text)
    html_text = ' '.join(html.text)
    if plain and ' '.join(plain.split()) != ' '.join(html_text.split()) and html_text.strip():
        result['alternative_html_text'] = html_text[:MAX_TEXT]
        if len(html_text) > MAX_TEXT:
            result['incomplete'].append('html_text_limit')
    result['html'] = '\n'.join(htmls)
    result['urls'] = html.links
    seen = {u['href'] for u in html.links}
    for url in URL.findall(plain):
        url = url.rstrip('.,;)')
        if url not in seen:
            result['urls'].append({'href': url, 'visible': url, 'mismatch': False})
            seen.add(url)
    if len(result['text']) > MAX_TEXT or len(result['html']) > MAX_TEXT or len(result['urls']) > 100:
        result['incomplete'].append('text_or_url_limit')
    result['text'] = result['text'][:MAX_TEXT]
    result['html'] = result['html'][:MAX_TEXT]
    result['urls'] = result['urls'][:100]
    return result
