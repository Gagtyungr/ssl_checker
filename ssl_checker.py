import ssl
import socket
import threading
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone

import tkinter as tk
from tkinter import ttk, scrolledtext

TIMEOUT = 10  #__________секунд/seconds

_ATTR_OID = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.5': 'SERIAL', '2.5.4.7': 'L',
    '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '0.9.2342.19200300.100.1.25': 'DC', '1.2.840.113549.1.9.1': 'E',
}
_SIG_OID = {
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.5':  'sha1WithRSAEncryption',
    '1.2.840.10045.4.3.2':   'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3':   'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4':   'ecdsa-with-SHA512',
    '1.3.101.112':           'ED25519',
    '1.3.101.113':           'ED448',
}
_RSA_OID  = '1.2.840.113549.1.1.1'
_EC_OID   = '1.2.840.10045.2.1'
_SAN_OID  = '2.5.29.17'
_CURVE_BITS = {
    '1.2.840.10045.3.1.7': 256, '1.3.132.0.34': 384, '1.3.132.0.35': 521,
    '1.3.101.110': 256, '1.3.101.111': 448,
}

#__________сеть: соединение/network: connection 
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
    """Единственное сетевое действие: TCP + TLS handshake -> DER сертификата -> close.
    Работает на любой сборке, где есть модуль ssl (включая Store/conda)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          #__________просроченные, самоподписанные/expired, self‑signed
    ctx.verify_mode = ssl.CERT_NONE     #__________нужна ИНФОРМАЦИЯ/INFORMATION is needed. 
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError(f'Порт {port} не отдал SSL-сертификат (похоже, это не HTTPS).')
    return der

#__________парсер/parser
def _read_tlv(buf: bytes, i: int):                      
    """Один TLV -> (tag, value_bytes, next_offset). Поддержка short/long length."""
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], 'big'); i += n
    return tag, buf[i:i + ln], i + ln


def _children(seq_val: bytes):
    """Список [(tag, value), ...] непосредственных элементов SEQUENCE/SET."""
    out, i = [], 0
    while i < len(seq_val):
        t, v, i = _read_tlv(seq_val, i)
        out.append((t, v))
    return out


def _decode_oid(b: bytes) -> str:
    if not b:
        return ''
    parts = [str(b[0] // 40), str(b[0] % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(val)); val = 0
    return '.'.join(parts)


def _text_of(value: bytes) -> str:
    for enc in ('utf-8', 'latin-1'):
        try:
            return value.decode(enc)
        except Exception:
            continue
    return value.hex()


def _format_name(name_val: bytes) -> str:
    parts = []
    for _rtag, rdn in _children(name_val):          
        for _atag, atv in _children(rdn):           
            kids = _children(atv)
            if len(kids) < 2:
                continue
            oid = _decode_oid(kids[0][1])
            label = _ATTR_OID.get(oid, oid)
            parts.append(f'{label}={_text_of(kids[1][1])}')
    return ', '.join(parts) or '(пусто)'


def _parse_time(tag: int, value: bytes):
    s = _text_of(value).strip()
    off = timedelta(0)
    if s.endswith('Z'):
        s = s[:-1]
    else:
        for sign_idx in range(len(s) - 1, 1, -1):  
            if s[sign_idx] in '+-':
                sign = 1 if s[sign_idx] == '+' else -1
                tzpart = s[sign_idx + 1:].replace(':', '')
                if len(tzpart) >= 4:
                    hh = int(tzpart[0:2]); mm = int(tzpart[2:4]) if len(tzpart) >= 4 else 0
                    off = sign * timedelta(hours=hh, minutes=mm)
                s = s[:sign_idx]
                break
    if '.' in s:
        s = s.split('.')[0]
    try:
        if tag == 0x17:                              
            yy = int(s[0:2]); yr = 2000 + yy if yy < 50 else 1900 + yy
            mo, da, hh, mi, se = (int(s[i:i + 2]) for i in (2, 4, 6, 8, 10))
        else:                                        
            yr = int(s[0:4])
            mo, da, hh, mi, se = (int(s[i:i + 2]) for i in (4, 6, 8, 10, 12))
        return datetime(yr, mo, da, hh, mi, se, tzinfo=timezone.utc) - off
    except Exception:
        return None


def _parse_spki(spki_val: bytes):
    """-> (key_alg:str|None, key_bits:int|None, sig_alg_from_tbs=None)."""
    kids = _children(spki_val)
    if not kids:
        return None, None
    alg_oid = None
    for _t, v in _children(kids[0][1]):            
        if _t == 0x06:
            alg_oid = _decode_oid(v); break
    if alg_oid == _RSA_OID:
        if len(kids) > 1 and kids[1][0] == 0x03 and kids[1][1]:
            inner = kids[1][1][1:]
            mk = _children(inner)
            if mk:
                modulus = int.from_bytes(mk[0][1], 'big')
                return 'RSA', modulus.bit_length()
        return 'RSA', None
    if alg_oid == _EC_OID:
        curve = None
        for _t, v in _children(kids[0][1]):
            if _t == 0x06 and _decode_oid(v) != _EC_OID:
                curve = _decode_oid(v)
        return 'EC', _CURVE_BITS.get(curve)
    if alg_oid in _SIG_OID:                          
        return _SIG_OID[alg_oid], _CURVE_BITS.get(alg_oid)
    return (_SIG_OID.get(alg_oid) or alg_oid or None), None


def _parse_extensions(ext_seq_val: bytes):
    """-> список SAN (dns/ip строки)."""
    sans = []
    for _t, ext in _children(ext_seq_val):           
        ek = _children(ext)
        if len(ek) < 2:
            continue
        if _decode_oid(ek[0][1]) != _SAN_OID:
            continue
        octet = ek[-1][1]                            
        for gtag, gval in _children(octet):          
            if gtag == 0x82:                         #__________dNSName 
                sans.append(_text_of(gval))
            elif gtag == 0x87:                       #__________iPAddress 
                if len(gval) == 4:
                    sans.append('.'.join(str(b) for b in gval))
                elif len(gval) == 16:
                    sans.append(':'.join(f'{gval[i]:02x}{gval[i+1]:02x}' for i in range(0, 16, 2)))
    return sans


def parse_der(der: bytes) -> dict:
    """Разбирает DER X.509 в dict без приватных API и без внешних библиотек."""
    root_kids = _children(_read_tlv(der, 0)[1])      
    tbs_val = root_kids[0][1]
    sig_alg = None
    if len(root_kids) > 1:                           
        sa = _children(root_kids[1][1])
        if sa and sa[0][0] == 0x06:
            sig_alg = _SIG_OID.get(_decode_oid(sa[0][1])) or _decode_oid(sa[0][1])

    kids = _children(tbs_val)
    idx = 0
    raw_ver = 0
    if kids and kids[0][0] == 0xA0:                  
        vi = _children(kids[0][1])
        if vi:
            raw_ver = int.from_bytes(vi[0][1], 'big')
        idx = 1
    serial = ''
    if idx < len(kids) and kids[idx][0] == 0x02:
        serial = format(int.from_bytes(kids[idx][1], 'big'), 'X'); idx += 1
    if idx < len(kids) and kids[idx][0] == 0x30:     
        sa = _children(kids[idx][1])
        if sa and sa[0][0] == 0x06 and not sig_alg:
            sig_alg = _SIG_OID.get(_decode_oid(sa[0][1])) or _decode_oid(sa[0][1])
        idx += 1
    issuer = _format_name(kids[idx][1]) if idx < len(kids) else ''; idx += 1
    nb = na = None
    if idx < len(kids) and kids[idx][0] == 0x30:     # validity
        vk = _children(kids[idx][1])
        if len(vk) >= 2:
            nb = _parse_time(vk[0][0], vk[0][1])
            na = _parse_time(vk[1][0], vk[1][1])
        idx += 1
    subject = _format_name(kids[idx][1]) if idx < len(kids) else ''; idx += 1
    key_alg = key_bits = None
    if idx < len(kids) and kids[idx][0] == 0x30:    
        key_alg, key_bits = _parse_spki(kids[idx][1]); idx += 1
    sans = []
    for t, v in kids[idx:]:                          
        if t == 0xA3:
            sans = _parse_extensions(v); break

    days = (na - datetime.now(timezone.utc)).days if na else None
    return {
        'subject': subject, 'issuer': issuer, 'serial': serial,
        'version': {0: 'v1', 1: 'v2', 2: 'v3'}.get(raw_ver, f'v{raw_ver}'),
        'sig_alg': sig_alg, 'key_alg': key_alg, 'key_bits': key_bits,
        'nb': nb, 'na': na, 'days': days, 'sans': sans,
    }

#__________проверка и статус/check and status
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

    try:
        info = parse_der(der)
    except Exception as e:
        res['err'] = f'Не удалось разобрать сертификат: {type(e).__name__}: {e}'
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

#__________отчёт/report
def report(r: dict) -> str:                                      
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

#__________GUI 
class App:                                                  
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

        #__________AI фикс/AI fix Ctrl+C / Ctrl+V 
        _is_windows = (e.tk.call('tk', 'windowingsystem') == 'win32')

        def _clip_fix(event):
            if not (event.state & 0x0004):
                return

            ks = (event.keysym or '').lower()

            if (_is_windows and event.keycode == 67) or ks in ('c', 'cyrillic_es', 'u0441', 'u0421'):
                event.widget.event_generate('<<Copy>>')
                return 'break'

            if (_is_windows and event.keycode == 86) or ks in ('v', 'cyrillic_ve', 'u0432', 'u0412'):
                event.widget.event_generate('<<Paste>>')
                return 'break'

        e.bind('<KeyPress>', _clip_fix)
        # ------------------------------------------------------

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
            'Будет выполнено TLS-соединение как в браузере\n'
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