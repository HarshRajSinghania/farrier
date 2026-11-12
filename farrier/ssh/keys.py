"""SSH public keys: blob parsing, sizes, OpenSSH SHA-256 fingerprints and signature checks. Pure.

The same blob format appears in a KEX reply (the server's host key, K_S), in known_hosts and in
authorized_keys, so host-key discovery and the authorized-key inventory share this module.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from farrier.ssh.wire import Reader, WireError

_CURVES = {"nistp256": (ec.SECP256R1, 256), "nistp384": (ec.SECP384R1, 384), "nistp521": (ec.SECP521R1, 521)}

# Plain key types (no certificates) the inventory understands.
KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")

# Host-key *signature* algorithm (what KEXINIT lists) -> key type in the blob.
SIG_TO_KEY = {"rsa-sha2-256": "ssh-rsa", "rsa-sha2-512": "ssh-rsa", "ssh-rsa": "ssh-rsa",
              "ssh-ed25519": "ssh-ed25519", "ssh-dss": "ssh-dss",
              "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384",
              "ecdsa-sha2-nistp521": "ecdsa-sha2-nistp521"}


@dataclass(frozen=True)
class PublicKey:
    type: str           # key type from the blob, e.g. "ssh-ed25519"
    bits: int
    blob: bytes

    @property
    def fingerprint_sha256(self) -> str:
        return fingerprint(self.blob)

    @property
    def b64(self) -> str:
        return base64.b64encode(self.blob).decode()

    @property
    def algorithm(self) -> str:
        """Family name for inventories: RSA, ECDSA, Ed25519, DSA."""
        t = self.type.removeprefix("sk-")
        return ("RSA" if t == "ssh-rsa" else "DSA" if t == "ssh-dss" else
                "Ed25519" if t.startswith("ssh-ed25519") else "ECDSA")

    @property
    def strength(self) -> int:
        """Approximate symmetric-equivalent security in bits (NIST SP 800-57), to rank keys."""
        if self.algorithm in ("Ed25519",):
            return 128
        if self.algorithm == "ECDSA":
            return self.bits // 2
        if self.algorithm == "DSA":
            return 80
        return 0 if self.bits < 1024 else 80 if self.bits < 2048 else 112 if self.bits < 3072 else \
            128 if self.bits < 7680 else 192 if self.bits < 15360 else 256


def fingerprint(blob: bytes) -> str:
    """OpenSSH format: ``SHA256:`` + unpadded base64 of the SHA-256 of the key blob."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_blob(blob: bytes) -> PublicKey:
    r = Reader(blob)
    try:
        kt = r.string().decode("ascii")
    except UnicodeDecodeError:
        raise WireError("key type is not ASCII") from None
    if kt == "ssh-rsa":
        r.mpint()                               # e
        bits = r.mpint().bit_length()
    elif kt == "ssh-dss":
        bits = r.mpint().bit_length()           # p
        r.mpint(), r.mpint(), r.mpint()
    elif kt in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        if len(r.string()) != 32:
            raise WireError("Ed25519 key is not 32 bytes")
        bits = 256
    elif kt.startswith(("ecdsa-sha2-", "sk-ecdsa-sha2-")):
        curve = r.string().decode("ascii", "replace")
        if curve not in _CURVES:
            raise WireError(f"unknown ECDSA curve {curve!r}")
        r.string()                              # Q
        bits = _CURVES[curve][1]
    else:
        raise WireError(f"unsupported key type {kt!r}")
    if kt.startswith("sk-"):
        r.string()                              # application ("ssh:")
    return PublicKey(kt, bits, blob)


def verify(blob: bytes, sig_blob: bytes, data: bytes) -> bool:
    """True when ``sig_blob`` (SSH signature encoding) is a valid signature of ``data`` by key ``blob``."""
    try:
        _verify(blob, sig_blob, data)
        return True
    except (InvalidSignature, WireError, ValueError):
        return False


def _verify(blob: bytes, sig_blob: bytes, data: bytes) -> None:
    k, s = Reader(blob), Reader(sig_blob)
    kt, alg, sig = k.string().decode(), s.string().decode(), s.string()
    if kt == "ssh-ed25519" and alg == "ssh-ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(k.string()).verify(sig, data)
    elif kt == "ssh-rsa" and alg in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"):
        e, n = k.mpint(), k.mpint()
        h = {"rsa-sha2-256": hashes.SHA256(), "rsa-sha2-512": hashes.SHA512(), "ssh-rsa": hashes.SHA1()}[alg]
        rsa.RSAPublicNumbers(e, n).public_key().verify(sig, data, padding.PKCS1v15(), h)
    elif kt.startswith("ecdsa-sha2-") and alg == kt:
        curve_cls, bits = _CURVES[k.string().decode()]
        point = k.string()
        rs = Reader(sig)
        der = encode_dss_signature(rs.mpint(), rs.mpint())
        h = hashes.SHA256() if bits == 256 else hashes.SHA384() if bits == 384 else hashes.SHA512()
        ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), point).verify(der, data, ec.ECDSA(h))
    elif kt == "ssh-dss" and alg == "ssh-dss":
        p, q, g, y = k.mpint(), k.mpint(), k.mpint(), k.mpint()
        if len(sig) != 40:
            raise WireError("DSA signature is not 40 bytes")
        der = encode_dss_signature(int.from_bytes(sig[:20], "big"), int.from_bytes(sig[20:], "big"))
        key = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key()
        key.verify(der, data, hashes.SHA1())
    else:
        raise WireError(f"signature {alg} does not match key type {kt}")
