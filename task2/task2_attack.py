

import sys
from task2_ke import (
    Credentials, run_handshake, Initiator, Responder, Message2,
    derive_keys, hmac_sha256, aead_encrypt, aead_decrypt, P
)

def run_replay_attack():
    print("=" * 70)
    print("Executing Replay Attack Simulation on Task 2 Modified Protocol")
    print("=" * 70)

    # Setup credentials
    alice_creds = Credentials.generate("Alice")
    bob_creds = Credentials.generate("Bob")

    # -----------------------------------------------------------------------
    # Session 1: Legitimate Handshake
    # -----------------------------------------------------------------------
    print("[+] Step 1: Executing a legitimate Session 1 to record traffic...")
    alice1 = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    bob1 = Responder(creds=bob_creds, peer_vk=alice_creds.vk)

    msg1_s1 = alice1.create_message1()
    msg2_s1 = bob1.process_message1(msg1_s1)
    msg3_s1 = alice1.process_message2(msg2_s1)
    bob1.process_message3(msg3_s1)

    print("    [Recorded] Valid Bob Message 2 signature metadata:")
    print(f"      sidB1: {msg2_s1.sidB.hex()}")
    print(f"      Y1:    {msg2_s1.Y.hex()[:32]}...")
    print(f"      sigB1: {msg2_s1.sigB.hex()[:32]}...")

    # -----------------------------------------------------------------------
    # Scenario: Leakage of DH exponent y1
    # -----------------------------------------------------------------------
    leaked_y1 = bob1._exposed_y
    print(f"\n[+] Step 2: Attacker acquires Bob's leaked DH exponent y1 from Session 1.")
    print(f"    Leaked y1: {hex(leaked_y1)[:42]}...")

    # -----------------------------------------------------------------------
    # Session 2: Fresh session initialized by Alice
    # -----------------------------------------------------------------------
    print("\n[+] Step 3: Alice starts a completely fresh Session 2...")
    alice2 = Initiator(creds=alice_creds, peer_vk=bob_creds.vk)
    msg1_s2 = alice2.create_message1()
    print("    Alice sends a fresh Message 1 (sidA2, X2)")
    print(f"      sidA2: {msg1_s2.sidA.hex()}")
    print(f"      X2:    {msg1_s2.X.hex()[:32]}...")

    # -----------------------------------------------------------------------
    # Attacker Action: Intercept, Forge MAC, Replay Signature
    # -----------------------------------------------------------------------
    print("\n[+] Step 4: Attacker intercepts Message 1 and crafts a malicious Message 2.")
    print("    -> Replaying Bob's identity component (sidB1, Y1, sigB1) from Session 1.")
    
    # Using the leaked y1 and Alice's fresh public value X2, the attacker computes Z for Session 2!
    X2_int = int.from_bytes(msg1_s2.X, byteorder="big")
    Z_attack = pow(X2_int, leaked_y1, P)
    
    # Derive the handshake authentication keys
    ka_attack, _, ks_attack, ks_prime_attack, _, _ = derive_keys(Z_attack)
    
    # Re-compute the MAC tag on Bob's certificate using the derived key
    tagB_attack = hmac_sha256(ka_attack, msg2_s1.certB)
    
    # Construct the forged Message 2
    msg2_attack = Message2(
        sidA=msg1_s2.sidA,       # Bind to current session's sidA
        sidB=msg2_s1.sidB,       # Replayed sidB from Session 1
        certB=msg2_s1.certB,     # Bob's certificate
        Y=msg2_s1.Y,             # Replayed Y from Session 1
        sigB=msg2_s1.sigB,       # Replayed valid signature component!
        tagB=tagB_attack         # Freshly forged MAC tag
    )

    # -----------------------------------------------------------------------
    # Deliver to Alice
    # -----------------------------------------------------------------------
    print("\n[+] Step 5: Delivering the spoofed Message 2 to Alice...")
    try:
        msg3_from_alice = alice2.process_message2(msg2_attack)
        print("    [SUCCESS] Alice accepted the replayed/spoofed Message 2!")
        print("    Alice verified Bob's replayed signature and forged MAC successfully.")
    except Exception as e:
        print(f"    [FAIL] Alice rejected the message: {e}")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Verification of Key Compromise
    # -----------------------------------------------------------------------
    print("\n[+] Step 6: Verifying Key Compromise Status...")
    print(f"    Alice's Derived Key (ks):       {alice2.ks.hex()}")
    print(f"    Attacker's Derived Key (ks):    {ks_attack.hex()}")
    assert alice2.ks == ks_attack, "Handshake keys do not match!"
    print("    [SUCCESS] Attacker successfully extracted identical application keys.")
    
    # Demonstrate data interception
    plaintext = b"Confidential financial transaction payload."
    nonce, ciphertext = aead_encrypt(alice2.ks_prime, plaintext)
    print(f"\n[+] Alice sends encrypted traffic: {ciphertext.hex()[:40]}...")
    
    decrypted_by_attacker = aead_decrypt(ks_prime_attack, nonce, ciphertext)
    print(f"    Attacker successfully decrypted data: '{decrypted_by_attacker.decode()}'")
    print("=" * 70)

if __name__ == "__main__":
    run_replay_attack()