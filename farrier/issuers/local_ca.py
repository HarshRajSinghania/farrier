"""A private CA for labs, internal-only endpoints and end-to-end testing.

Lifetimes follow the public CA/B Forum schedule by default so you can rehearse the
47-day world today (set lifetime_days to override, e.g. 30 for a stress test).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..policy import max_lifetime_days
from ..vault import load_private_key, save_private_key


class LocalCA:
    automated_dcv = True

    def __init__(self, data_dir: Path, name: str = "Farrier Local CA", lifetime_days: int | None = None,
                 simulate_date: str | None = None):
        self.dir = Path(data_dir) / "local-ca"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lifetime_days = lifetime_days
        self.simulate_date = simulate_date
        key_path, cert_path = self.dir / "ca.key", self.dir / "ca.pem"
        if not cert_path.exists():
            key = ec.generate_private_key(ec.SECP384R1())
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            now = datetime.now(UTC)
            cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                                   critical=True)
                    .sign(key, hashes.SHA384()))
            save_private_key(key_path, key, data_dir)  # sealed under the master key, owner-only
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key = load_private_key(key_path, data_dir)
        self.cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        self.ca_pem = cert_path.read_text()

    def issue(self, csr_pem: str, names: list[str]) -> tuple[str, str]:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("CSR signature invalid")
        now = datetime.now(UTC)
        on = datetime.fromisoformat(self.simulate_date) if self.simulate_date else now
        days = self.lifetime_days or max_lifetime_days(on)
        cert = (x509.CertificateBuilder()
                .subject_name(csr.subject).issuer_name(self.cert.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.key, hashes.SHA384()))
        return cert.public_bytes(serialization.Encoding.PEM).decode(), self.ca_pem
