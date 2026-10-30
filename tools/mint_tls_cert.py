"""Mint the self-signed TLS certificate the emulator's API listener serves.

The Meraki add-on's account form validates Base URL against ^https:// because
the real Dashboard API is HTTPS-only; serving TLS keeps the emulator
configurable exactly like api.meraki.com.

The host Python has no `cryptography`, but Splunk's bundled interpreter does,
so this runs inside the container:

    docker cp tools/mint_tls_cert.py emulanet-splunk:/tmp/mint_tls_cert.py
    docker exec -e LD_LIBRARY_PATH=/opt/splunk/lib -e CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1 \
        emulanet-splunk /opt/splunk/bin/python3 /tmp/mint_tls_cert.py
    docker cp emulanet-splunk:/tmp/emulanet.crt config/tls/server.crt
    docker cp emulanet-splunk:/tmp/emulanet.key config/tls/server.key

SANs cover every name the add-on and the verify scripts connect with.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "host.docker.internal"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northwind Retail Group (emulator)"),
])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("host.docker.internal"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

with open("/tmp/emulanet.crt", "wb") as fh:
    fh.write(cert.public_bytes(serialization.Encoding.PEM))
with open("/tmp/emulanet.key", "wb") as fh:
    fh.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
print("wrote /tmp/emulanet.crt and /tmp/emulanet.key")
