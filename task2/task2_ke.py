
from __future__ import annotations

import hmac
import os
import secrets
import uuid
import cryptography
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# ffdhe3072 domain parameters (RFC 7919)
# ---------------------------------------------------------------------------

_P_HEX = (
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
    "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
    "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
    "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
    "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
    "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
    "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03405A2F4EEECFD"
    "02BF0EFBACF52FFFFFFFFFFFFFFFF"
)

P: int = int(_P_HEX, 16)
G: int = 2
P_BYTE_LEN: int = (P.bit_length() + 7) // 8


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def int_to_bytes_fixed(n: int) -> bytes:
    return n.to_bytes(P_BYTE_LEN, byteorder="big")

def new_sid() -> bytes:
    return uuid.uuid4().bytes

def new_dh_exponent() -> int:
    while True:
        x = secrets.randbelow(P - 1)
        if x != 0:
            return x

def dh_check(value: int) -> None:
    if not (1 < value < P - 1):
        raise ValueError(f"DH public value out of range: {value}")

# ---------------------------------------------------------------------------
# HKDF & Cryptographic Helpers
# ---------------------------------------------------------------------------

def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    h = HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()

def hkdf_expand(prk: bytes, info: str, length: int) -> bytes:
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info.encode())
    return hkdf.derive(prk)

def derive_keys(Z: int):
    Z_bytes = int_to_bytes_fixed(Z)
    # Task 2: Salt is empty (b"")
    hs = hkdf_extract(ikm=Z_bytes, salt=b"")

    ka       = hkdf_expand(hs, info="resp-hs-auth",  length=32)
    ka_prime = hkdf_expand(hs, info="init-hs-auth",  length=32)
    ms       = hkdf_extract(ikm=b"", salt=hs)
    ks       = hkdf_expand(ms, info="resp-ap-aead",  length=32)
    ks_prime = hkdf_expand(ms, info="init-ap-aead",  length=32)

    return ka, ka_prime, ks, ks_prime, hs, ms

def generate_ecdsa_keypair():
    sk = ec.generate_private_key(ec.SECP256R1())
    vk = sk.public_key()
    return sk, vk

def ecdsa_sign(sk: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return sk.sign(message, ec.ECDSA(hashes.SHA256()))

def ecdsa_verify(vk: ec.EllipticCurvePublicKey, message: bytes, sig: bytes) -> None:
    vk.verify(sig, message, ec.ECDSA(hashes.SHA256()))

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_sha256_verify(key: bytes, data: bytes, tag: bytes) -> None:
    expected = hmac_sha256(key, data)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC verification failed")

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

@dataclass
class Credentials:
    name: str
    sk: ec.EllipticCurvePrivateKey
    vk: ec.EllipticCurvePublicKey
    cert: bytes

    @staticmethod
    def generate(name: str) -> Credentials:
        sk, vk = generate_ecdsa_keypair()
        cert = vk.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) + name.encode()
        return Credentials(name=name, sk=sk, vk=vk, cert=cert)

# ---------------------------------------------------------------------------
# Protocol Messages
# ---------------------------------------------------------------------------

@dataclass
class Message1:
    sidA: bytes
    X: bytes

@dataclass
class Message2:
    sidA: bytes
    sidB: bytes
    certB: bytes
    Y: bytes
    sigB: bytes
    tagB: bytes

@dataclass
class Message3:
    sidA: bytes
    sidB: bytes
    certA: bytes
    sigA: bytes
    tagA: bytes

# ---------------------------------------------------------------------------
# Handshake Entities
# ---------------------------------------------------------------------------

class Initiator:
    def __init__(self, creds: Credentials, peer_vk: ec.EllipticCurvePublicKey):
        self._creds    = creds
        self._peer_vk  = peer_vk
        self._state    = "idle"
        self._x: Optional[int]   = None
        self._X_int: Optional[int] = None
        self._sidA: Optional[bytes] = None
        self.ks: Optional[bytes]       = None
        self.ks_prime: Optional[bytes] = None

    def create_message1(self) -> Message1:
        assert self._state == "idle"
        self._sidA = new_sid()
        self._x = new_dh_exponent()
        self._X_int = pow(G, self._x, P)
        dh_check(self._X_int)
        
        X_bytes = int_to_bytes_fixed(self._X_int)
        self._state = "sent_msg1"
        return Message1(sidA=self._sidA, X=X_bytes)

    def process_message2(self, msg2: Message2) -> Message3:
        assert self._state == "sent_msg1"
        sidB = msg2.sidB

        Y_int = int.from_bytes(msg2.Y, byteorder="big")
        dh_check(Y_int)

        Z = pow(Y_int, self._x, P)
        ka, ka_prime, ks, ks_prime, hs, ms = derive_keys(Z=Z)

        # Task 2 payload: msg = sidB || Y (No nA)
        sig_payload_B = sidB + msg2.Y
        try:
            ecdsa_verify(self._peer_vk, sig_payload_B, msg2.sigB)
        except Exception as exc:
            raise ValueError(f"B's signature verification failed: {exc}") from exc

        hmac_sha256_verify(ka, msg2.certB, msg2.tagB)

        X_bytes = int_to_bytes_fixed(self._X_int)
        # Task 2 payload: msg = sidA || X (No nB)
        sig_payload_A = self._sidA + X_bytes
        sigA = ecdsa_sign(self._creds.sk, sig_payload_A)
        tagA = hmac_sha256(ka_prime, self._creds.cert)

        self._x = None
        self.ks       = ks
        self.ks_prime = ks_prime
        self._state = "done"
        
        return Message3(
            sidA=self._sidA, sidB=sidB, certA=self._creds.cert, sigA=sigA, tagA=tagA
        )

class Responder:
    def __init__(self, creds: Credentials, peer_vk: ec.EllipticCurvePublicKey):
        self._creds   = creds
        self._peer_vk = peer_vk
        self._state   = "idle"
        self._X_bytes: Optional[bytes] = None
        self._sidA: Optional[bytes] = None
        self._sidB: Optional[bytes] = None
        self._ka_prime: Optional[bytes] = None
        self.ks: Optional[bytes]       = None
        self.ks_prime: Optional[bytes] = None
        
        # Simulated vulnerability storage field to track session context leak
        self._exposed_y: Optional[int] = None

    def process_message1(self, msg1: Message1) -> Message2:
        assert self._state == "idle"
        self._sidA = msg1.sidA
        self._sidB = new_sid()

        X_int = int.from_bytes(msg1.X, byteorder="big")
        dh_check(X_int)
        self._X_bytes = int_to_bytes_fixed(X_int)

        y = new_dh_exponent()
        Y_int = pow(G, y, P)
        dh_check(Y_int)

        Z = pow(X_int, y, P)
        ka, ka_prime, ks, ks_prime, hs, ms = derive_keys(Z=Z)

        # Retain y value to allow attack simulation script to read the leak
        self._exposed_y = y

        Y_bytes = int_to_bytes_fixed(Y_int)
        # Task 2 payload: msg = sidB || Y (No nA)
        sig_payload_B = self._sidB + Y_bytes
        sigB = ecdsa_sign(self._creds.sk, sig_payload_B)
        tagB = hmac_sha256(ka, self._creds.cert)

        self._ka_prime = ka_prime
        self.ks       = ks
        self.ks_prime = ks_prime
        self._state = "received_msg1"
        
        return Message2(
            sidA=self._sidA, sidB=self._sidB, certB=self._creds.cert, Y=Y_bytes, sigB=sigB, tagB=tagB
        )

    def process_message3(self, msg3: Message3) -> None:
        assert self._state == "received_msg1"
        # Task 2 payload: msg = sidA || X (No nB)
        sig_payload_A = msg3.sidA + self._X_bytes
        try:
            ecdsa_verify(self._peer_vk, sig_payload_A, msg3.sigA)
        except Exception as exc:
            raise ValueError(f"A's signature verification failed: {exc}") from exc

        hmac_sha256_verify(self._ka_prime, msg3.certA, msg3.tagA)
        self._ka_prime = None
        self._state = "done"

def run_handshake(alice_creds: Credentials, bob_creds: Credentials) -> tuple[Initiator, Responder]:
    alice = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob   = Responder(creds=bob_creds,   peer_vk=alice_creds.vk)
    
    msg1 = alice.create_message1()
    msg2 = bob.process_message1(msg1)
    msg3 = alice.process_message2(msg2)
    bob.process_message3(msg3)
    return alice, bob





