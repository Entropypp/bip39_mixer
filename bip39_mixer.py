#!/usr/bin/env python3
import sys
import argparse
import hashlib
import struct
import binascii
from mnemonic import Mnemonic

mnemo = Mnemonic("english")
BIP39_WORDLIST = mnemo.wordlist

# ---------------------------------------------------------------------------
# SeedSigner-style manual HMAC-SHA256 (no Python hmac module)
# ---------------------------------------------------------------------------
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    block_size = 64  # SHA256 block size

    if len(key) > block_size:
        key = hashlib.sha256(key).digest()

    key = key.ljust(block_size, b"\x00")

    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5C) for x in key)

    inner = hashlib.sha256(ipad + data).digest()
    return hashlib.sha256(opad + inner).digest()

# ---------------------------------------------------------------------------
# SeedSigner-style HKDF (Extract + Expand) using HMAC-SHA256
# ---------------------------------------------------------------------------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # For 32 bytes, a single block is enough
    if length > 32:
        raise ValueError("This HKDF implementation only supports length <= 32")
    t1 = hmac_sha256(prk, info + b"\x01")
    return t1[:length]

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
def word_to_index(word: str) -> int:
    cleaned = word.strip().lower()
    try:
        return BIP39_WORDLIST.index(cleaned)
    except ValueError:
        print(f"[!] Error: '{cleaned}' is not a valid BIP-39 word.")
        sys.exit(1)

def clean_word_list(phrase_str: str) -> list:
    if not phrase_str:
        return []
    delimit = ',' if ',' in phrase_str else ' '
    return [w.strip().lower() for w in phrase_str.split(delimit) if w.strip()]

# ---------------------------------------------------------------------------
# SeedSigner-style dice entropy: base-6 → base-2
# Interpret dice rolls as a big base-6 integer, then convert to bytes.
# ---------------------------------------------------------------------------
def dice_to_entropy_bytes(dice_rolls: str) -> bytes:
    """
    Convert a sequence of dice rolls (chars '1'-'6') into entropy bytes
    via base-6 → base-2 conversion (SeedSigner-style approach).
    """
    value = 0
    for roll in dice_rolls:
        if roll not in "123456":
            print(f"[!] Error: Character '{roll}' is not a valid 1-6 die value.")
            sys.exit(1)
        digit = int(roll) - 1  # map 1-6 → 0-5
        value = value * 6 + digit

    # Convert big integer to big-endian bytes (minimal length)
    if value == 0:
        return b"\x00"

    out = bytearray()
    while value > 0:
        out.insert(0, value & 0xFF)
        value >>= 8
    return bytes(out)

# ---------------------------------------------------------------------------
# SeedSigner-style HKDF-Extract over structured entropy
# ---------------------------------------------------------------------------
def calculate_mix_hkdf(seed_phrase: str, dice_rolls: str = None, additional_seed: str = None) -> bytes:
    """
    SeedSigner-style HKDF (Extract + Expand) over structured entropy:
    - base seed words (index + UTF-8)
    - dice entropy (base-6 → base-2)
    - additional seed words
    """
    hkdf_salt = b"UniversalEntropyMixerSaltV1"
    info = b"UniversalEntropyMixerHKDFv1"

    msg = b""

    # Base seed phrase
    words = clean_word_list(seed_phrase)
    if words:
        print(f"[*] Extracting base seed phrase ({len(words)} words)...")
        msg += b"[BASE_SEED_START]"
        for word in words:
            word_idx = word_to_index(word)
            msg += struct.pack(">H", word_idx)
            msg += word.encode("utf-8")
        msg += b"[BASE_SEED_END]"

    # Dice rolls (base-6 → base-2 entropy)
    if dice_rolls:
        print(f"[*] Extracting dice data sequence: '{dice_rolls}'")
        dice_entropy = dice_to_entropy_bytes(dice_rolls)
        msg += b"[DICE_ROLLS_START]"
        msg += dice_entropy
        msg += b"[DICE_ROLLS_END]"

    # Additional seed phrase
    if additional_seed:
        extra_words = clean_word_list(additional_seed)
        print(f"[*] Extracting additional seed sequence ({len(extra_words)} words)...")
        msg += b"[ADDITIONAL_SEED_START]"
        for word in extra_words:
            word_idx = word_to_index(word)
            msg += struct.pack(">H", word_idx)
            msg += word.encode("utf-8")
        msg += b"[ADDITIONAL_SEED_END]"

    # HKDF Extract
    prk = hkdf_extract(hkdf_salt, msg)
    # HKDF Expand to 32 bytes
    okm = hkdf_expand(prk, info, 32)
    return okm

# ---------------------------------------------------------------------------
# BIP-39 mnemonic generation
# ---------------------------------------------------------------------------
def generate_bip39_phrase(pure_entropy: bytes) -> str:
    print("[*] Processing entropy directly into a 24-word mnemonic...")
    return mnemo.to_mnemonic(pure_entropy)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Universal Secure Entropy Mixer (SeedSigner-style HKDF & dice) & 24-Word Recovery Phrase Generator"
    )
    
    parser.add_argument('--seed_phrase', type=str, default="", help="Base seed phrase (comma or space split).")
    parser.add_argument('--dice_rolls', type=str, default=None, help="Concatenated string of dice rolls (1-6).")
    parser.add_argument('--additional_seed', type=str, default=None, help="Additional seed words to mix.")

    args = parser.parse_args()

    if not args.seed_phrase and not args.dice_rolls:
        parser.print_help()
        print("\n[!] Error: You must supply a --seed_phrase, --dice_rolls, or both.")
        sys.exit(1)

    pure_entropy = calculate_mix_hkdf(
        seed_phrase=args.seed_phrase,
        dice_rolls=args.dice_rolls,
        additional_seed=args.additional_seed
    )

    final_phrase = generate_bip39_phrase(pure_entropy)
    entropy_hex_str = binascii.hexlify(pure_entropy).decode('ascii')

    print("\n" + "="*70)
    print("🔒 UNIFORM MASTER ENTROPY HEX (32 bytes):")
    print(entropy_hex_str)
    print("-"*70)
    print("📋 FINAL COMPLETED 24-WORD RECOVERY STRING:")
    print(f"\n{final_phrase}\n")
    print("="*70)

if __name__ == "__main__":
    main()
