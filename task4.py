"""
Laboratory Session 4 – Task 4: Masquerade Attack on Unsigned Protocol Variant
===========================================================================
"""

from __future__ import annotations

import hmac
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

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

def int_to_bytes_fixed(n: int) -> bytes:
    return n.to_bytes(P_BYTE_LEN, byteorder="big")

def new_sid() -> bytes:
    return uuid.uuid4().bytes

def new_nonce() -> bytes:
    return os.urandom(16)

def new_dh_exponent() -> int:
    while True:
        x = secrets.randbelow(P - 1)
        if x != 0:
            return x

def dh_check(value: int) -> None:
    if not (1 < value < P - 1):
        raise ValueError("DH public value out of range")

def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    h = HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()

def hkdf_expand(prk: bytes, info: str, length: int) -> bytes:
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info.encode())
    return hkdf.derive(prk)

def derive_keys(Z: int, nA: bytes, nB: bytes):
    Z_bytes = int_to_bytes_fixed(Z)
    hs = hkdf_extract(ikm=Z_bytes, salt=nA + nB)
    ka       = hkdf_expand(hs, info="resp-hs-auth",  length=32)
    ka_prime = hkdf_expand(hs, info="init-hs-auth",  length=32)
    ms = hkdf_extract(ikm=b"", salt=hs)
    ks       = hkdf_expand(ms, info="resp-ap-aead",  length=32)
    ks_prime = hkdf_expand(ms, info="init-ap-aead",  length=32)
    return ka, ka_prime, ks, ks_prime, hs, ms

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_sha256_verify(key: bytes, data: bytes, tag: bytes) -> None:
    expected = hmac_sha256(key, data)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC verification failed")

@dataclass
class Credentials:
    name: str
    vk: ec.EllipticCurvePublicKey
    cert: bytes

    @staticmethod
    def generate(name: str) -> "Credentials":
        sk = ec.generate_private_key(ec.SECP256R1())
        vk = sk.public_key()
        cert = vk.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) + name.encode()
        return Credentials(name=name, vk=vk, cert=cert)

# ---------------------------------------------------------------------------
# PATCHED PROTOCOL MESSAGES (Signatures removed for Task 4)
# ---------------------------------------------------------------------------

@dataclass
class Message1:
    sidA: bytes
    X: bytes
    nA: bytes

@dataclass
class Message2:
    sidA: bytes
    sidB: bytes
    certB: bytes
    Y: bytes
    nB: bytes
    tagB: bytes  # sigB removed entirely based on lab4task4.patch

@dataclass
class Message3:
    sidA: bytes
    sidB: bytes
    certA: bytes
    tagA: bytes  # sigA removed entirely based on lab4task4.patch

# ---------------------------------------------------------------------------
# PATCHED RESPONDER (Bob - Unsigned Variant)
# ---------------------------------------------------------------------------

class UnsignedResponder:
    """Simulates Bob running the modified protocol without signature checks."""
    def __init__(self, creds: Credentials):
        self._creds = creds
        self._state = "idle"
        self._y: Optional[int] = None
        self._Y_int: Optional[int] = None
        self._nB: Optional[bytes] = None
        self._nA: Optional[bytes] = None
        self._sidA: Optional[bytes] = None
        self._sidB: Optional[bytes] = None
        self._ka_prime: Optional[bytes] = None
        self.ks: Optional[bytes] = None
        self.ks_prime: Optional[bytes] = None

    def process_message1(self, msg1: Message1) -> Message2:
        assert self._state == "idle"
        self._sidA = msg1.sidA
        self._nA = msg1.nA
        self._sidB = new_sid()

        X_int = int.from_bytes(msg1.X, byteorder="big")
        dh_check(X_int)

        self._y = new_dh_exponent()
        self._Y_int = pow(G, self._y, P)
        dh_check(self._Y_int)

        Z = pow(X_int, self._y, P)
        self._nB = new_nonce()

        ka, ka_prime, ks, ks_prime, hs, ms = derive_keys(Z=Z, nA=self._nA, nB=self._nB)

        self._y = None
        Y_bytes = int_to_bytes_fixed(self._Y_int)

        # Generate responder MAC tag using the derived key
        tagB = hmac_sha256(ka, self._creds.cert)

        self._ka_prime = ka_prime
        self.ks = ks
        self.ks_prime = ks_prime

        self._state = "received_msg1"
        
        # Message2 goes out with no sigB component
        return Message2(
            sidA=self._sidA,
            sidB=self._sidB,
            certB=self._creds.cert,
            Y=Y_bytes,
            nB=self._nB,
            tagB=tagB,
        )

    def process_message3(self, msg3: Message3) -> None:
        assert self._state == "received_msg1"
        # Skip signature verification and directly check the initiator's MAC
        hmac_sha256_verify(self._ka_prime, msg3.certA, msg3.tagA)
        self._ka_prime = None
        self._state = "done"

# ---------------------------------------------------------------------------
# TASK 4: MASQUERADE ATTACK SIMULATION
# ---------------------------------------------------------------------------

def run_masquerade_attack(alice_creds: Credentials, bob_creds: Credentials):
    """
    Attacker M impersonates Alice to establish a session with Bob.
    Since signatures are dropped, M can forge the MAC tag by manually 
    computing the shared secret Z using its own ephemeral key.
    """
    print("\n[~] Initializing masquerade attack scenario...")

    # Bob is completely honest but running the insecure protocol variant
    bob = UnsignedResponder(creds=bob_creds)

    # Attacker M generates its own rogue ephemeral DH key pair
    x_M = new_dh_exponent()
    X_M_int = pow(G, x_M, P)
    X_M_bytes = int_to_bytes_fixed(X_M_int)
    
    sid_M = new_sid()
    n_M = new_nonce()

    # M sends rogue Message 1 pretending to be Alice
    msg1_from_M = Message1(sidA=sid_M, X=X_M_bytes, nA=n_M)
    print("[>] Step 1: Attacker M sent malicious Message1 to Bob (spoofing Alice).")

    # Bob processes it and sends back Message 2
    msg2_from_bob = bob.process_message1(msg1_from_M)
    print("[>] Step 2: Bob accepted the message and replied with Message2.")

    # Critical Step: M intercepts Bob's Y and computes the shared secret Z
    Y_bob_int = int.from_bytes(msg2_from_bob.Y, byteorder="big")
    Z_M = pow(Y_bob_int, x_M, P)

    # M runs the key derivation locally to extract the authentication key (ka_prime)
    _, ka_prime_M, _, _, _, _ = derive_keys(Z=Z_M, nA=n_M, nB=msg2_from_bob.nB)

    # M grabs Alice's public certificate and computes a valid MAC tag (tagA)
    tagA_M = hmac_sha256(ka_prime_M, alice_creds.cert)

    # M constructs and sends the final forged Message 3
    msg3_from_M = Message3(
        sidA=sid_M,
        sidB=msg2_from_bob.sidB,
        certA=alice_creds.cert, # Alice's legitimate public identity
        tagA=tagA_M,            # Forged MAC tag matching Bob's key schedule
    )
    print("[>] Step 3: Attacker M sent forged Message3 (valid MAC, no signature required).")

    # Bob verifies the received Message 3
    try:
        bob.process_message3(msg3_from_M)
        print("\n[SUCCESS] Attack fully succeeded! Bob verified the MAC tag and completed the handshake.")
        print("          Bob now believes he shares a secure session with Alice, but he is talking to M.")
    except ValueError as e:
        print(f"\n[FAIL] Handshake failed or was rejected: {e}")

if __name__ == "__main__":
    # Setup test credentials for the simulation
    alice_identity = Credentials.generate("Alice")
    bob_identity = Credentials.generate("Bob")
    
    run_masquerade_attack(alice_identity, bob_identity)