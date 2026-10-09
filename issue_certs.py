"""Выпускает свой CA и кросс-сертификат на корень Минцифры с ограничением по доменам.

Вход:  domains.txt, russian_trusted_root_ca.cer (PEM или DER)
Выход: my_ca.crt - импортировать в Firefox с галкой «доверять сайтам»
       cross.crt - импортировать без галок

Свой CA дополнительно ограничен зонами доменов (ru, su, ...), так что даже при утечке
ключа подделать можно только сайты в этих зонах.

Ключ CA по умолчанию не сохраняется. С --save-key он сохраняется зашифрованным в
my_ca.key; при следующих запусках используется он, и перевыпускается только cross.crt.
"""
import argparse
import datetime as dt
import getpass
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path("russian_trusted_root_ca.cer")
DOMAINS = Path("domains.txt")
CA_CRT, CA_KEY, CROSS = Path("my_ca.crt"), Path("my_ca.key"), Path("cross.crt")

CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "My RU Constraint CA")])
KU_CA = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False,
)
PEM = serialization.Encoding.PEM


def load_cert(path):
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def read_domains():
    out = []
    for line in DOMAINS.read_text(encoding="utf-8").splitlines():
        d = line.split("#", 1)[0].strip().lower().rstrip(".")
        if d.startswith("*."):
            d = d[2:]
        if d and d not in out:
            out.append(d)
    if not out:
        sys.exit(f"{DOMAINS} пуст")
    return out


def name_constraints(names):
    return x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(n) for n in names], excluded_subtrees=None
    )


def permitted(cert):
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None
    return [g.value for g in nc.permitted_subtrees or []]


def same_key(a, b):
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    return a.public_bytes(serialization.Encoding.DER, fmt) == b.public_bytes(serialization.Encoding.DER, fmt)


def new_ca(zones, now):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(CA_NAME).issuer_name(CA_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(KU_CA, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(name_constraints(zones), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def ask_new_password():
    while True:
        p1 = getpass.getpass("Пароль для my_ca.key: ")
        p2 = getpass.getpass("Ещё раз: ")
        if p1 and p1 == p2:
            return p1.encode()
        print("Пароли пусты или не совпадают")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--save-key", action="store_true", help="сохранить ключ CA (зашифрованным) в my_ca.key")
    args = ap.parse_args()

    root = load_cert(ROOT)
    if root.subject != root.issuer:
        sys.exit(f"{ROOT} не самоподписанный корень: {root.subject.rfc4514_string()}")
    fp = hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    print(f"Корень:  {root.subject.rfc4514_string()}")
    print(f"SHA-256: {fp}  <- сверь с отпечатком на gosuslugi.ru/crt")

    domains = read_domains()
    zones = sorted({d.rsplit(".", 1)[-1] for d in domains})
    now = dt.datetime.now(dt.timezone.utc)

    if CA_KEY.exists():
        pw = getpass.getpass("Пароль от my_ca.key: ").encode()
        try:
            key = serialization.load_pem_private_key(CA_KEY.read_bytes(), pw)
        except ValueError:
            sys.exit("Неверный пароль")
        ca = load_cert(CA_CRT)
        if not same_key(ca.public_key(), key.public_key()):
            sys.exit("my_ca.key не подходит к my_ca.crt")
        ca_zones = permitted(ca)
        missing = [z for z in zones if ca_zones is not None and z not in ca_zones]
        if missing:
            sys.exit(
                f"my_ca ограничен зонами {ca_zones}, а нужны ещё {missing}.\n"
                "Удали my_ca.key и my_ca.crt и запусти заново - выпустится новый CA."
            )
        reused = True
    else:
        key, ca = new_ca(zones, now)
        CA_CRT.write_bytes(ca.public_bytes(PEM))
        if args.save_key:
            CA_KEY.write_bytes(key.private_bytes(
                PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(ask_new_password()),
            ))
        reused = False

    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cross = (
        x509.CertificateBuilder()
        .subject_name(root.subject).issuer_name(ca.subject)
        .public_key(root.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(min(root.not_valid_after_utc, ca.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(KU_CA, critical=True)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
        .add_extension(name_constraints(domains), critical=True)
        .sign(key, hashes.SHA256())
    )
    CROSS.write_bytes(cross.public_bytes(PEM))

    print(f"\nДомены ({len(domains)}): {', '.join(domains)}")
    print(f"Зоны CA: {', '.join(permitted(ca) or ['без ограничений'])}")
    print("\nFirefox -> Certificate Manager -> Authorities:")
    if reused:
        print("  1. Удали старый «Russian Trusted Root CA» (тот, что под My RU Constraint CA)")
        print("  2. Import cross.crt - БЕЗ галок")
    else:
        print("  1. Удали старые «My RU Constraint CA» и «Russian Trusted Root CA», если есть")
        print("  2. Import my_ca.crt - с галкой «Trust this CA to identify websites»")
        print("  3. Import cross.crt - БЕЗ галок")
        print("  Ключ CA " + ("сохранён в my_ca.key (зашифрован)" if args.save_key else "не сохранён"))


if __name__ == "__main__":
    main()
