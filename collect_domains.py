"""Собирает домены из TLS-сертификатов сайтов.

Вход:  sites.txt   - по одному сайту на строку (host, host:port или URL), # - комментарий
Выход: domains.txt - домены для nameConstraints. Просмотри и поправь перед выпуском.

Сайты на публичных CA (не Минцифры) пропускаются - им серт Минцифры не нужен.
"""
import socket
import ssl
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509.oid import NameOID

SITES = Path("sites.txt")
OUT = Path("domains.txt")
MINTSIFRY_MARK = "Russian Trusted"  # CN промежуточного: Russian Trusted Sub CA


def read_lines(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def parse_site(s):
    u = urlsplit(s if "://" in s else "//" + s)
    return u.hostname, u.port or 443


def fetch_leaf(host, port):
    # Проверку отключаем: цепочку Минцифры система не знает. Нам нужны только имена.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def norm(name):
    name = name.strip().lower().rstrip(".")
    return name[2:] if name.startswith("*.") else name


def issuer_cn(cert):
    attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.issuer.rfc4514_string()


def main():
    sources = defaultdict(set)

    for site in read_lines(SITES):
        host, port = parse_site(site)
        try:
            cert = fetch_leaf(host, port)
        except Exception as e:
            print(f"[ошибка]  {host}: {e}")
            continue

        issuer = issuer_cn(cert)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []

        if MINTSIFRY_MARK not in issuer:
            print(f"[пропуск] {host}: публичный CA ({issuer})")
            continue

        print(f"[ok]      {host}: {', '.join(names)}")
        for n in names + [host]:
            sources[norm(n)].add(host)

    # Убираем имена, покрытые другими (www.x.ru покрыт x.ru)
    all_names = set(sources)
    final = sorted(
        (n for n in all_names if not any(n.endswith("." + o) for o in all_names)),
        key=lambda n: n.split(".")[::-1],
    )
    for n in all_names - set(final):
        parent = next(o for o in final if n.endswith("." + o))
        sources[parent] |= sources[n]

    if OUT.exists():
        OUT.replace(OUT.with_suffix(".txt.bak"))

    width = max((len(n) for n in final), default=0)
    lines = [
        "# Домены, для которых будет действовать сертификат Минцифры (вместе с поддоменами).",
        "# Можно укоротить до базового домена (id.sber.ru -> sber.ru) или удалить лишнее.",
        "# Справа - с каких сайтов домен собран.",
        "",
        *(f"{n:<{width}}  # {', '.join(sorted(sources[n]))}" for n in final),
    ]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nЗаписано {len(final)} доменов в {OUT}. Проверь файл и запусти issue_certs.py")


if __name__ == "__main__":
    main()
