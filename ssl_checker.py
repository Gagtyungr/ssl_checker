import ssl
import socket
import base64
import tempfile
import os
import threading
from urllib.parse import urlparse
from datetime import datetime, timezone

import tkinter as tk
from tkinter import ttk, scrolledtext

TIMEOUT = 10 # секунд, сетевое ограничение.

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

_NAME_MAP = {
    'commonName': 'CN', 'organizationName': 'O', 'organizationalUnitNam': 'OU',
    'countryName': 'C', 'stateOrProvinceName': 'ST', 'localityName': 'L',
    'domainComponent': 'DC', 'emailAddress': 'E', 'serialNumber': 'SERIAL',
}


def extract_host_port(raw: str):
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('Введите ссылку')
    if '://' not in raw:
        raw = 'https://' + raw
    p = urlparse(raw)
    host = p.hostname
    if not host:
        raise ValueError(f'Не понял адрес: {raw}')
    port = p.port or 443
    if port == 80:
        port = 443
    return host, port


def fetch_der(host: str, port: int) -> bytes:
    """Единственное сетевое действие: TCP + TLS handsnake -> DER сертификата -> close."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False                      # Просрочка!
    ctx.verify_mode = ssl.CERT_NONE                 # Запрос инфы.
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError(f'Порт {port} не отдал SSL-сертификат (это не HTTPS).')
        return der


def _der_to_pem(der: bytes) -> str:
    b = base64.encodebytes(der).decode('ascii')
    return '-----BEGIN CERTIFICATE-----\n' + b + '-----END CERTIFICATE-----\n'


def _parse_when(s):
    """'May 10 12:34:56 2026 GMT' -> aware datetime (UTC)."""
    if not s:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(s)
        return dt.astimezone(timezone.uts) if dt.tzinfo else dt.replace(tzinfo=timezone.uts)
    except Exception:
        pass
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
        try:
            return datetime.strftime(s, fmt).replace(tzinfo=timezone.uts)
        except Exception:
            continue
    return None


def _fmt_name(tuples) -> str:
    parts = []
    for rdn in (tuples or()):
        for av in rdn:
            k, v = av[0], av[1]
            parts.append(f'{_NAME_MAP.get(k,k)}={v}')
    return ', '.join(parts) or '(пусто)'


def _sans_from_dict(info) -> list:
    out = []
    for typ, val in (info.get('subjectAltName') or ()):
        if typ in ('DNS', 'IP Address', 'IPAddress'):
            out.append(str(val))
    return out


def decode_stdlib(der: bytes) -> dict:
    """Разбор через стандартный модуль ssl (без внешних пакетов)."""
    pem = _der_to_pem(der)
    fd, path = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(pem)
        raw = ssl._test_decode_cert(path)         
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    nb = _parse_when(raw.get('notBefore'))
    na = _parse_when(raw.get('notAfter'))
    days = (na - datetime.now(timezone.utc)).days if na else None
    return {
        'subject': _fmt_name(raw.get('subject')),
        'issuer': _fmt_name(raw.get('issuer')),
        'serial': str(raw.get('serialNumber', '')),
        'version': {0: 'v1', 1: 'v2', 2: 'v3'}.get(raw.get('version', 2), 'v3'),
        'nb': nb, 'na': na, 'days': days,
        'sans': _sans_from_dict(raw),
    }


def _blank_info() -> dict:
    return {'subject': '', 'issuer': '', 'serial': '', 'version': 'v3',
            'nb': None, 'na': None, 'days': None, 'sans': []}


def enrich_crypto(der: bytes, info: dict) -> None:
    """Доп. поля (алгоритм подписи, тип/размер ключа) — только если cryptography стоит."""
    if not _HAS_CRYPTO:
        return
    try:
        c = x509.load_der_x509_certificate(der, default_backend())
        info['sig_alg'] = getattr(c.signature_algorithm_oid, '_name',
                                  str(c.signature_algorithm_oid))
        info['key_alg'] = type(c.public_key()).__name__.replace('PublicKey', '')
        try:
            info['key_bits'] = c.public_key().key_size
        except Exception:
            pass
        if not info.get('sans'):
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info['sans'] = ext.value.get_values_for_type(x509.DNSName)
        if not info.get('na'):
            try:
                info['nb'] = c.not_valid_before_utc
                info['na'] = c.not_valid_after_utc
            except AttributeError:
                info['nb'] = c.not_valid_before.replace(tzinfo=timezone.utc)
                info['na'] = c.not_valid_after.replace(tzinfo=timezone.utc)
            info['days'] = (info['na'] - datetime.now(timezone.utc)).days
    except Exception:
        pass


def check_ssl(host: str, port: int) -> dict:
    res = {'host': host, 'port': port, 'ok': False, 'err': None}
    try:
        der = fetch_der(host, port)
    except socket.gaierror:
        res['err'] = f"DNS: имя '{host}' не разрешается"; return res
    except socket.timeout:
        res['err'] = f'Таймаут {TIMEOUT} с — {host}:{port} не отвечает'; return res
    except ConnectionRefusedError:
        res['err'] = f'Соединение отклонено ({host}:{port}) — порт закрыт / не SSL'; return res
    except ssl.SSLError as e:
        res['err'] = f'SSL error: {e}'; return res
    except OSError as e:
        res['err'] = f'Network error: {e}'; return res
    except Exception as e:
        res['err'] = f'{type(e).__name__}: {e}'; return res

    
    info, err_parse = None, None
    try:
        info = decode_stdlib(der)
    except Exception as e:
        err_parse = e
    if _HAS_CRYPTO:
        if info is None:
            info = _blank_info()
        try:
            enrich_crypto(der, info)
        except Exception as e:
            err_parse = err_parse or e
    if not info or (not info.get('na') and not info.get('subject')):
        res['err'] = f'Не удалось разобрать сертификат: {err_parse or "нет данных"}'
        return res

    days = info.get('days')
    if days is None:
        status = '?  Срок не определён'
    elif days < 0:
        status = f'✖  ИСТЁК ({-days} дн. назад)'
    elif days <= 30:
        status = f'⚠  Истекает через {days} дн.'
    else:
        status = f'✔  Действителен ({days} дн.)'
    info['status'] = status
    res.update(ok=True, **info)
    return res


def report(r: dict) -> str: # Отчёт.
    bar = '═' * 50
    L = [bar, f'  Хост : {r["host"]}:{r["port"]}', bar]
    if r.get('err'):
        L.append(f'\n  ⛔  {r["err"]}')
        return '\n'.join(L)
    for lab, key in [('Subject', 'subject'), ('Issuer ', 'issuer'),
                     ('Serial ', 'serial'), ('Version', 'version'),
                     ('SigAlg ', 'sig_alg'), ('KeyAlg ', 'key_alg')]:
        if r.get(key):
            L.append(f'  {lab}: {r[key]}')
    if r.get('key_bits'):
        L.append(f'  KeyBits: {r["key_bits"]}')
    L.append('')
    if r.get('nb'):
        L.append(f'  Действует с : {r["nb"]:%Y-%m-%d %H:%M:%S} UTC')
    if r.get('na'):
        L.append(f'  Действует до: {r["na"]:%Y-%m-%d %H:%M:%S} UTC')
    L.append('')
    L.append(f'  ► ИТОГ: {r.get("status", "?")}')
    if r.get('sans'):
        L.append(f'\n  DNS/IP в сертификате ({len(r["sans"])}):')
        for s in r['sans'][:15]:
            L.append(f'    · {s}')
        if len(r['sans']) > 15:
            L.append(f'    … ещё {len(r["sans"]) - 15}')
    L.append('\n' + bar)
    return '\n'.join(L)


class App:                          #GUI
    def __init__(self, root):
        self.root = root
        root.title('SSL Checker')
        root.geometry('640x520')
        root.minsize(460, 360)
        try:
            ttk.Style().theme_use('clam')
        except Exception:
            pass
        self._ui()

    def _ui(self):
        top = ttk.Frame(self.root, padding=(10, 10, 10, 4))
        top.pack(fill=tk.X)
        ttk.Label(top, text='Ссылка:').pack(side=tk.LEFT)
        self.var = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.var, width=44)
        e.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        e.bind('<Return>', lambda _: self._go())
        e.focus_set()
        self.btn = ttk.Button(top, text='Тест', command=self._go, width=8)
        self.btn.pack(side=tk.LEFT)

        box = ttk.LabelFrame(self.root, text=' Результат ', padding=4)
        box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 2))
        self.txt = scrolledtext.ScrolledText(
            box, wrap=tk.WORD, font=('Consolas', 10),
            bg='#1e1e1e', fg='#d0d0d0', insertbackground='#fff',
            relief=tk.FLAT, padx=6, pady=4, state=tk.DISABLED)
        self.txt.pack(fill=tk.BOTH, expand=True)
        self._write(
            'Введите ссылку и нажмите «Тест» (или Enter).\n\n'
            'Примеры:  example.com   https://www.google.com   github.com\n\n'
            'Будет выполнено ОДНО TLS-соединение (как в браузере)\n'
            'и показаны данные публичного SSL-сертификата и срок его действия.')

        ttk.Label(self.root, wraplength=620, justify=tk.LEFT, foreground='#888',
                  font=('Segoe UI', 8), padding=(10, 2, 10, 6),
                  text='ℹ  1 соединение · без HTTP-запросов · без сканирования портов · '
                       'без отправки данных наружу · работает локально').pack(fill=tk.X)
    def _go(self):
        raw = self.var.get().strip()
        if not raw:
            self._write('⚠  Введите ссылку.'); return
        try:
            host, port = extract_host_port(raw)
        except ValueError as e:
            self._write(f'⚠  {e}'); return
        self.btn.config(state=tk.DISABLED, text='…')
        self._write(f'Подключение {host}:{port} … (1 соединение, таймаут {TIMEOUT} с)')
        threading.Thread(target=self._work, args=(host, port), daemon=True).start()

    def _work(self, host, port):
        try:
            text = report(check_ssl(host, port))
        except Exception as e:
            text = f'⛔  Сбой: {type(e).__name__}: {e}'
        self.root.after(0, self._write, text)
        self.root.after(0, lambda: self.btn.config(state=tk.NORMAL, text='Тест'))

    def _write(self, t):
        self.txt.config(state=tk.NORMAL)
        self.txt.delete('1.0', tk.END)
        self.txt.insert(tk.END, t)
        self.txt.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == '__main__':
    main()
    