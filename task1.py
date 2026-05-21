"""
Laboratory Session 4 – Task 1: Authenticated Key-Exchange Protocol
===================================================================
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
from cryptography.hazmat.primitives.kdf.hkdf import  HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# ffdhe3072 domain parameters (RFC 7919)
# ---------------------------------------------------------------------------

# fmt: off
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
# fmt: on

P: int = int(_P_HEX, 16)
G: int = 2

# Byte length of p — all DH public values are encoded to this length.
P_BYTE_LEN: int = (P.bit_length() + 7) // 8  # 384 bytes for ffdhe3072


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def int_to_bytes_fixed(n: int) -> bytes:
    """Encode integer n as a big-endian byte string of exactly P_BYTE_LEN bytes
    (padded with leading zeros as required by the protocol)."""
    return n.to_bytes(P_BYTE_LEN, byteorder="big")


def new_sid() -> bytes:
    """Return a fresh session-ID encoded as a 16-byte string (UUID)."""
    return uuid.uuid4().bytes  # 16 bytes


def new_nonce() -> bytes:
    """Return 16 cryptographically random bytes."""
    return os.urandom(16)


def new_dh_exponent() -> int:
    """Return a non-zero random DH exponent in [1, p-2]."""
    while True:
        x = secrets.randbelow(P - 1)  # x in [0, p-2]
        if x != 0:
            return x


def dh_check(value: int) -> None:
    """Abort (raise) if value is not in the open interval (1, p-1)."""
    if not (1 < value < P - 1):
        raise ValueError(
            f"DH public value out of range: must satisfy 1 < v < p-1, got {value}"
        )


def erase(*names) -> None:
    """Simulate secure erasure by doing nothing — callers set vars to None."""
    # In Python we cannot truly zero memory; we signal erasure by None assignment.
    pass


# ---------------------------------------------------------------------------
# HKDF helpers (HKDF-SHA-256)
# ---------------------------------------------------------------------------


def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    """HKDF-Extract(salt, ikm) → pseudo-random key (PRK)."""
    # The cryptography library's HKDF bundles Extract+Expand; we use HMAC
    # directly for Extract so we can keep the PRK for multiple Expand calls.
    h = HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk: bytes, info: str, length: int) -> bytes:
    """HKDF-Expand(PRK, info, L) → output key material of `length` bytes."""
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info.encode(),
    )
    return hkdf.derive(prk)


def derive_keys(Z: int, nA: bytes, nB: bytes):
    """Full key schedule.

    Returns (ka, ka_prime, ks, ks_prime, hs, ms).
    hs and ms are returned so callers can erase them after use.
    """
    Z_bytes = int_to_bytes_fixed(Z)

    # Step 1 – handshake secret
    hs = hkdf_extract(ikm=Z_bytes, salt=nA + nB)

    # Step 2 – handshake authentication keys
    ka       = hkdf_expand(hs, info="resp-hs-auth",  length=32)
    ka_prime = hkdf_expand(hs, info="init-hs-auth",  length=32)

    # Step 3 – master secret
    ms = hkdf_extract(ikm=b"", salt=hs)

    # Step 4 – application-layer AEAD keys
    ks       = hkdf_expand(ms, info="resp-ap-aead",  length=32)
    ks_prime = hkdf_expand(ms, info="init-ap-aead",  length=32)

    return ka, ka_prime, ks, ks_prime, hs, ms


# ---------------------------------------------------------------------------
# ECDSA P-256 / SHA-256 helpers
# ---------------------------------------------------------------------------


def generate_ecdsa_keypair():
    """Generate an ECDSA P-256 key pair (sk, vk)."""
    sk = ec.generate_private_key(ec.SECP256R1())
    vk = sk.public_key()
    return sk, vk


def ecdsa_sign(sk: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign message with ECDSA P-256 / SHA-256; return DER-encoded signature."""
    return sk.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(vk: ec.EllipticCurvePublicKey, message: bytes, sig: bytes) -> None:
    """Verify DER-encoded ECDSA P-256 / SHA-256 signature; raise on failure."""
    vk.verify(sig, message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# HMAC-SHA256 helpers
# ---------------------------------------------------------------------------


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return HMAC-SHA256(key, data)."""
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_sha256_verify(key: bytes, data: bytes, tag: bytes) -> None:
    """Verify HMAC-SHA256 in constant time; raise ValueError on mismatch."""
    expected = hmac_sha256(key, data)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC verification failed")



# ---------------------------------------------------------------------------
# AES-GCM AEAD helpers (application-data layer)
# ---------------------------------------------------------------------------
# Key assignment after handshake:
#   ks_prime  →  initiator (A) encrypts, responder (B) decrypts
#   ks        →  responder (B) encrypts, initiator (A) decrypts


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM under *key*.

    A fresh 12-byte random nonce is generated for every call.
    Returns (nonce, ciphertext+tag) — the nonce must be sent alongside
    the ciphertext so the receiver can decrypt.
    """
    nonce = os.urandom(12)          # 96-bit nonce, fresh per message
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate *ciphertext* with AES-256-GCM under *key*.

    Raises cryptography.exceptions.InvalidTag if authentication fails
    (e.g. ciphertext or AAD has been tampered with).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# Party credentials
# ---------------------------------------------------------------------------


@dataclass
class Credentials:
    """Long-term identity material for one party."""
    name: str
    sk: ec.EllipticCurvePrivateKey
    vk: ec.EllipticCurvePublicKey
    cert: bytes  # In a real system, a DER-encoded X.509 cert; here a stub.

    @staticmethod
    def generate(name: str) -> "Credentials":
        sk, vk = generate_ecdsa_keypair()
        # Stub certificate: public key in DER + name bytes
        cert = vk.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) + name.encode()
        return Credentials(name=name, sk=sk, vk=vk, cert=cert)


# ---------------------------------------------------------------------------
# Protocol messages (simple data-transfer objects)
# ---------------------------------------------------------------------------


@dataclass
class Message1:
    """A → B  :  sidA, X, nA  (sidB is not yet known to A; B generates it)"""
    sidA: bytes
    X: bytes     # g^x mod p, encoded as P_BYTE_LEN big-endian bytes
    nA: bytes


@dataclass
class Message2:
    """B → A  :  sidA, sidB, certB, Y, nB, sigB, tagB"""
    sidA: bytes
    sidB: bytes
    certB: bytes
    Y: bytes     # g^y mod p, encoded as P_BYTE_LEN big-endian bytes
    nB: bytes
    sigB: bytes
    tagB: bytes


@dataclass
class Message3:
    """A → B  :  sidA, sidB, certA, sigA, tagA"""
    sidA: bytes
    sidB: bytes
    certA: bytes
    sigA: bytes
    tagA: bytes


# ---------------------------------------------------------------------------
# Initiator (Alice / A)
# ---------------------------------------------------------------------------


class Initiator:
    """
    Alice acts as the initiator of the handshake.

    State machine:
      idle → sent_msg1 → done
    """

    def __init__(self, creds: Credentials, peer_vk: ec.EllipticCurvePublicKey):
        self._creds    = creds
        self._peer_vk  = peer_vk  # Bob's long-term verification key
        self._state    = "idle"

        # Ephemeral state (will be erased after use)
        self._x: Optional[int]   = None
        self._X_int: Optional[int] = None
        self._nA: Optional[bytes] = None
        self._sidA: Optional[bytes] = None
        # Note: sidB is not known until Message 2 is received from B

        # Output keys
        self.ks: Optional[bytes]       = None
        self.ks_prime: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Step 1 – produce Message 1
    # ------------------------------------------------------------------

    def create_message1(self) -> Message1:
        """Generate ephemeral DH key and nonce; compose Message 1.

        A only generates its own session ID (sidA) here.
        sidB is generated by B upon receiving Message 1 and
        is first learned by A when Message 2 arrives.
        """
        assert self._state == "idle"

        # A's session identifier (sidB will be assigned by B)
        self._sidA = new_sid()

        # Ephemeral DH exponent and public value
        self._x = new_dh_exponent()
        self._X_int = pow(G, self._x, P)

        # Abort if out of range
        dh_check(self._X_int)

        # Fresh initiator nonce
        self._nA = new_nonce()

        X_bytes = int_to_bytes_fixed(self._X_int)

        self._state = "sent_msg1"
        return Message1(
            sidA=self._sidA,
            X=X_bytes,
            nA=self._nA,
        )

    # ------------------------------------------------------------------
    # Step 2 – process Message 2, produce Message 3
    # ------------------------------------------------------------------

    def process_message2(self, msg2: Message2) -> Message3:
        """Verify B's message; derive keys; compose Message 3.

        A learns sidB from Message 2 (B chose it) and uses it
        throughout the rest of the handshake.
        """
        assert self._state == "sent_msg1"

        # --- Learn sidB from B's message ---
        sidB = msg2.sidB

        # --- Decode B's DH public value ---
        Y_int = int.from_bytes(msg2.Y, byteorder="big")
        dh_check(Y_int)  # Abort if Y ∉ (1, p-1)

        # --- Compute shared secret ---
        # Z = Y^x mod p
        Z = pow(Y_int, self._x, P)

        # --- Derive all keys ---
        ka, ka_prime, ks, ks_prime, hs, ms = derive_keys(
            Z=Z, nA=self._nA, nB=msg2.nB
        )

        # --- Verify B's signature: sigB covers nA || sidB || Y ---
        sig_payload_B = self._nA + sidB + msg2.Y
        try:
            ecdsa_verify(self._peer_vk, sig_payload_B, msg2.sigB)
        except Exception as exc:
            raise ValueError(f"B's signature verification failed: {exc}") from exc

        # --- Verify B's MAC tag (constant-time): tagB = HMAC-SHA256(ka, certB) ---
        hmac_sha256_verify(ka, msg2.certB, msg2.tagB)

        # --- Erase intermediate secrets no longer needed ---
        Z      = None   # noqa: F841  (simulate erase)
        hs     = None   # noqa: F841
        ms     = None   # noqa: F841
        ka     = None   # noqa: F841

        # --- Build Message 3 ---
        # sigA = Sign(skA, nB || sidA || X)
        X_bytes     = int_to_bytes_fixed(self._X_int)
        sig_payload_A = msg2.nB + self._sidA + X_bytes
        sigA = ecdsa_sign(self._creds.sk, sig_payload_A)

        # tagA = HMAC-SHA256(ka_prime, certA)
        tagA = hmac_sha256(ka_prime, self._creds.cert)

        # Erase ka_prime after use
        ka_prime = None  # noqa: F841

        # Erase ephemeral DH secret
        self._x = None

        # Store application keys
        self.ks       = ks
        self.ks_prime = ks_prime

        self._state = "done"
        return Message3(
            sidA=self._sidA,
            sidB=sidB,
            certA=self._creds.cert,
            sigA=sigA,
            tagA=tagA,
        )


# ---------------------------------------------------------------------------
# Responder (Bob / B)
# ---------------------------------------------------------------------------


class Responder:
    """
    Bob acts as the responder of the handshake.

    State machine:
      idle → received_msg1 → done
    """

    def __init__(self, creds: Credentials, peer_vk: ec.EllipticCurvePublicKey):
        self._creds   = creds
        self._peer_vk = peer_vk   # Alice's long-term verification key
        self._state   = "idle"

        # Ephemeral state (erased after use)
        self._y: Optional[int]      = None
        self._Y_int: Optional[int]  = None
        self._nB: Optional[bytes]   = None
        self._nA: Optional[bytes]   = None
        self._X_bytes: Optional[bytes] = None
        self._sidA: Optional[bytes] = None
        self._sidB: Optional[bytes] = None

        # Shared key schedule state (needed to verify msg3)
        self._ka_prime: Optional[bytes] = None

        # Output keys
        self.ks: Optional[bytes]       = None
        self.ks_prime: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Step 1 – process Message 1, produce Message 2
    # ------------------------------------------------------------------

    def process_message1(self, msg1: Message1) -> Message2:
        """Receive A's DH value; generate sidB and own DH value; compose Message 2.

        B generates sidB here — it is not provided by A in Message 1.
        sidB is then communicated back to A as part of Message 2.
        """
        assert self._state == "idle"

        self._sidA = msg1.sidA
        self._nA   = msg1.nA

        # B generates its own session identifier
        self._sidB = new_sid()

        # --- Decode A's DH public value ---
        X_int = int.from_bytes(msg1.X, byteorder="big")
        dh_check(X_int)  # Abort if X ∉ (1, p-1)

        # Store X_bytes for later verification in msg3 processing
        self._X_bytes = int_to_bytes_fixed(X_int)

        # --- Ephemeral DH key ---
        self._y     = new_dh_exponent()
        self._Y_int = pow(G, self._y, P)
        dh_check(self._Y_int)

        # --- Compute shared secret ---
        # Z = X^y mod p
        Z = pow(X_int, self._y, P)

        # --- Fresh responder nonce ---
        self._nB = new_nonce()

        # --- Derive all keys ---
        ka, ka_prime, ks, ks_prime, hs, ms = derive_keys(
            Z=Z, nA=self._nA, nB=self._nB
        )

        # --- Erase ephemeral DH secret (y no longer needed) ---
        self._y = None
        Z       = None  # noqa: F841
        hs      = None  # noqa: F841
        ms      = None  # noqa: F841

        # --- Compute B's signature: sigB = Sign(skB, nA || sidB || Y) ---
        Y_bytes = int_to_bytes_fixed(self._Y_int)
        sig_payload_B = self._nA + self._sidB + Y_bytes
        sigB = ecdsa_sign(self._creds.sk, sig_payload_B)

        # --- Compute B's MAC: tagB = HMAC-SHA256(ka, certB) ---
        tagB = hmac_sha256(ka, self._creds.cert)

        # Erase ka after use; keep ka_prime for verifying msg3
        ka             = None  # noqa: F841
        self._ka_prime = ka_prime

        # Store application keys
        self.ks       = ks
        self.ks_prime = ks_prime

        self._state = "received_msg1"
        return Message2(
            sidA=self._sidA,
            sidB=self._sidB,
            certB=self._creds.cert,
            Y=Y_bytes,
            nB=self._nB,
            sigB=sigB,
            tagB=tagB,
        )

    # ------------------------------------------------------------------
    # Step 2 – process Message 3
    # ------------------------------------------------------------------

    def process_message3(self, msg3: Message3) -> None:
        """Verify A's message; complete handshake."""
        assert self._state == "received_msg1"

        # --- Verify A's signature: sigA covers nB || sidA || X ---
        sig_payload_A = self._nB + msg3.sidA + self._X_bytes
        try:
            ecdsa_verify(self._peer_vk, sig_payload_A, msg3.sigA)
        except Exception as exc:
            raise ValueError(f"A's signature verification failed: {exc}") from exc

        # --- Verify A's MAC tag (constant-time): tagA = HMAC-SHA256(ka_prime, certA) ---
        hmac_sha256_verify(self._ka_prime, msg3.certA, msg3.tagA)

        # --- Erase ka_prime after use ---
        self._ka_prime = None

        self._state = "done"


# ---------------------------------------------------------------------------
# High-level handshake runner (ties together A and B)
# ---------------------------------------------------------------------------


def run_handshake(
    alice_creds: Credentials,
    bob_creds: Credentials,
) -> tuple[Initiator, Responder]:
    """Execute a full handshake and return (alice, bob) with populated keys."""

    alice = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob   = Responder(creds=bob_creds,   peer_vk=alice_creds.vk)

    # --- Message 1: A → B  (sidA, X, nA) ---
    # A does not know sidB yet; B will generate it upon receiving Message 1.
    msg1 = alice.create_message1()

    # --- Message 2: B → A ---
    msg2 = bob.process_message1(msg1)

    # --- Message 3: A → B ---
    msg3 = alice.process_message2(msg2)
    bob.process_message3(msg3)

    return alice, bob


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------


def _setup():
    """Generate credentials for Alice and Bob."""
    alice_creds = Credentials.generate("Alice")
    bob_creds   = Credentials.generate("Bob")
    return alice_creds, bob_creds


def test_normal_handshake_succeeds():
    """Normal handshake completes without exceptions."""
    alice_creds, bob_creds = _setup()
    alice, bob = run_handshake(alice_creds, bob_creds)
    assert alice.ks       is not None
    assert alice.ks_prime is not None
    assert bob.ks         is not None
    assert bob.ks_prime   is not None
    print("[PASS] test_normal_handshake_succeeds")


def test_both_derive_same_keys():
    """Alice and Bob derive identical application keys."""
    alice_creds, bob_creds = _setup()
    alice, bob = run_handshake(alice_creds, bob_creds)
    assert alice.ks       == bob.ks,       "ks mismatch"
    assert alice.ks_prime == bob.ks_prime, "ks_prime mismatch"
    print("[PASS] test_both_derive_same_keys")


def test_invalid_dh_value_rejected():
    """A DH public value of 1 or p-1 must be rejected."""
    alice_creds, bob_creds = _setup()

    # Inject a bad X = 1
    alice = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob   = Responder(creds=bob_creds,   peer_vk=alice_creds.vk)

    msg1 = alice.create_message1()

    # Tamper: replace X with 1 (out of range)
    bad_X = int_to_bytes_fixed(1)
    bad_msg1 = Message1(sidA=msg1.sidA, X=bad_X, nA=msg1.nA)
    try:
        bob.process_message1(bad_msg1)
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass

    # Inject a bad X = p-1
    bad_X2 = int_to_bytes_fixed(P - 1)
    bad_msg1b = Message1(sidA=msg1.sidA, X=bad_X2, nA=msg1.nA)
    try:
        bob.process_message1(bad_msg1b)
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass

    print("[PASS] test_invalid_dh_value_rejected")


def test_modified_signature_rejected():
    """Flipping a byte in sigB causes A to reject Message 2."""
    alice_creds, bob_creds = _setup()
    alice = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob   = Responder(creds=bob_creds,   peer_vk=alice_creds.vk)

    msg1 = alice.create_message1()
    msg2 = bob.process_message1(msg1)

    # Flip the first byte of sigB
    bad_sigB = bytes([msg2.sigB[0] ^ 0xFF]) + msg2.sigB[1:]
    bad_msg2 = Message2(
        sidA=msg2.sidA, sidB=msg2.sidB, certB=msg2.certB,
        Y=msg2.Y, nB=msg2.nB, sigB=bad_sigB, tagB=msg2.tagB,
    )
    try:
        alice.process_message2(bad_msg2)
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass

    print("[PASS] test_modified_signature_rejected")


def test_modified_mac_tag_rejected():
    """Flipping a byte in tagB causes A to reject Message 2."""
    alice_creds, bob_creds = _setup()
    alice = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob   = Responder(creds=bob_creds,   peer_vk=alice_creds.vk)

    msg1 = alice.create_message1()
    msg2 = bob.process_message1(msg1)

    # Flip the last byte of tagB
    bad_tagB = msg2.tagB[:-1] + bytes([msg2.tagB[-1] ^ 0xFF])
    bad_msg2 = Message2(
        sidA=msg2.sidA, sidB=msg2.sidB, certB=msg2.certB,
        Y=msg2.Y, nB=msg2.nB, sigB=msg2.sigB, tagB=bad_tagB,
    )
    try:
        alice.process_message2(bad_msg2)
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass

    print("[PASS] test_modified_mac_tag_rejected")


def test_different_sessions_derive_different_keys():
    """Two independent sessions produce distinct key material."""
    alice_creds, bob_creds = _setup()

    alice1, bob1 = run_handshake(alice_creds, bob_creds)
    alice2, bob2 = run_handshake(alice_creds, bob_creds)

    assert alice1.ks != alice2.ks,             "ks should differ across sessions"
    assert alice1.ks_prime != alice2.ks_prime, "ks_prime should differ across sessions"
    print("[PASS] test_different_sessions_derive_different_keys")


def test_aead_application_data_exchange():
    """After a successful handshake, both traffic directions encrypt/decrypt correctly.

    Direction A → B: Alice encrypts with ks_prime; Bob decrypts with ks_prime.
    Direction B → A: Bob   encrypts with ks;       Alice decrypts with ks.
    """
    alice_creds, bob_creds = _setup()
    alice, bob = run_handshake(alice_creds, bob_creds)

    # --- A → B ---
    plaintext_a = b"Hello Bob, this is Alice."
    nonce_a, ct_a = aead_encrypt(alice.ks_prime, plaintext_a)
    recovered_a   = aead_decrypt(bob.ks_prime,   nonce_a, ct_a)
    assert recovered_a == plaintext_a, "A→B decryption mismatch"

    # --- B → A ---
    plaintext_b = b"Hello Alice, this is Bob."
    nonce_b, ct_b = aead_encrypt(bob.ks,   plaintext_b)
    recovered_b   = aead_decrypt(alice.ks, nonce_b, ct_b)
    assert recovered_b == plaintext_b, "B→A decryption mismatch"

    print("[PASS] test_aead_application_data_exchange")


def test_aead_tampered_ciphertext_rejected():
    """Flipping one byte in a ciphertext must cause AES-GCM to reject it."""
    from cryptography.exceptions import InvalidTag

    alice_creds, bob_creds = _setup()
    alice, bob = run_handshake(alice_creds, bob_creds)

    # Alice encrypts a message to Bob (A → B direction, key = ks_prime)
    nonce, ct = aead_encrypt(alice.ks_prime, b"Sensitive payload")

    # Flip the first byte of the ciphertext
    tampered_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]

    try:
        aead_decrypt(bob.ks_prime, nonce, tampered_ct)
        raise AssertionError("Should have raised InvalidTag")
    except InvalidTag:
        pass

    print("[PASS] test_aead_tampered_ciphertext_rejected")


def run_all_tests():
    print("=" * 60)
    print("Running Lab 4 Task 1 – AKE Protocol Tests")
    print("=" * 60)
    test_normal_handshake_succeeds()
    test_both_derive_same_keys()
    test_invalid_dh_value_rejected()
    test_modified_signature_rejected()
    test_modified_mac_tag_rejected()
    test_different_sessions_derive_different_keys()
    test_aead_application_data_exchange()
    test_aead_tampered_ciphertext_rejected()
    print("=" * 60)
    print("All tests passed.")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_all_tests()
