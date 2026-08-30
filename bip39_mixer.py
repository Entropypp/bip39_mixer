#!/usr/bin/env python3
import sys
import argparse
import hashlib
import hmac
import struct
import binascii
from mnemonic import Mnemonic

# Initialize the official BIP-39 library for English word mapping
mnemo = Mnemonic("english")
BIP39_WORDLIST = mnemo.wordlist

def word_to_index(word: str) -> int:
    """Finds the precise index (0-2047) of a word in the official BIP-39 dictionary."""
    cleaned = word.strip().lower()
    try:
        return BIP39_WORDLIST.index(cleaned)
    except ValueError:
        print(f"[!] Error: '{cleaned}' is not a valid BIP-39 word.")
        sys.exit(1)

def clean_word_list(phrase_str: str) -> list:
    """Parses and sanitizes comma-delimited or space-delimited word strings."""
    if not phrase_str:
        return []
    delimit = ',' if ',' in phrase_str else ' '
    return [w.strip().lower() for w in phrase_str.split(delimit) if w.strip()]

def calculate_mix_hkdf(seed_phrase: str, dice_rolls: str = None, additional_seed: str = None) -> bytes:
    """
    Chronologically structures inputs with distinct field separation prefixes
    and extracts a uniform 256-bit entropy pool using HMAC-SHA256 (HKDF Step 1).
    """
    # A fixed, cryptographically strong salt acts as the HKDF Extract keying material
    hkdf_salt = b"UniversalEntropyMixerSaltV1"
    hmac_ctx = hmac.new(hkdf_salt, msg=None, digestmod=hashlib.sha256)
    
    # Process Base Phrase state sequence
    words = clean_word_list(seed_phrase)
    if words:
        print(f"[*] Extracting base seed phrase ({len(words)} words)...")
        # Domain separation to isolate data blocks clearly
        hmac_ctx.update(b"[BASE_SEED_START]") 
        for word in words:
            word_idx = word_to_index(word)
            hmac_ctx.update(struct.pack(">H", word_idx))
            hmac_ctx.update(word.encode('utf-8'))
        hmac_ctx.update(b"[BASE_SEED_END]")
            
    # Specification 1: Concatenated Dice Roll string mixing
    if dice_rolls:
        print(f"[*] Extracting dice data sequence: '{dice_rolls}'")
        hmac_ctx.update(b"[DICE_ROLLS_START]")
        for roll in dice_rolls:
            if roll not in "123456":
                print(f"[!] Error: Character '{roll}' is not a valid 1-6 die value.")
                sys.exit(1)
            hmac_ctx.update(roll.encode('utf-8'))
        hmac_ctx.update(b"[DICE_ROLLS_END]")
            
    # Specification 2: Additional Seed Phrase processing
    if additional_seed:
        extra_words = clean_word_list(additional_seed)
        print(f"[*] Extracting additional seed sequence ({len(extra_words)} words)...")
        hmac_ctx.update(b"[ADDITIONAL_SEED_START]")
        for word in extra_words:
            word_idx = word_to_index(word)
            hmac_ctx.update(struct.pack(">H", word_idx))
            hmac_ctx.update(word.encode('utf-8'))
        hmac_ctx.update(b"[ADDITIONAL_SEED_END]")

    return hmac_ctx.digest()

def generate_bip39_phrase(pure_entropy: bytes) -> str:
    """
    Accepts 32-bytes of pure, uniform entropy and converts it into a complete
    24-word BIP-39 recovery phrase sentence.
    """
    print("[*] Processing entropy directly into a 24-word mnemonic...")
    # This automatically splits the 256 bits into 11-bit chunks, appends the
    # 8-bit checksum, and joins them into a single string.
    return mnemo.to_mnemonic(pure_entropy)

def main():
    parser = argparse.ArgumentParser(
        description="Universal Secure Entropy Mixer & 24-Word Recovery Phrase Generator"
    )
    
    parser.add_argument('--seed_phrase', type=str, default="", help="Base seed phrase (comma or space split).")
    parser.add_argument('--dice_rolls', type=str, default=None, help="Concatenated string of dice rolls (1-6).")
    parser.add_argument('--additional_seed', type=str, default=None, help="Additional seed words to mix.")

    args = parser.parse_args()

    if not args.seed_phrase and not args.dice_rolls:
        parser.print_help()
        print("\n[!] Error: You must supply a --seed_phrase, --dice_rolls, or both.")
        sys.exit(1)

    # 1. Uniform Cryptographic Extraction (Replaced standard hash & PBKDF2 stretching)
    pure_entropy = calculate_mix_hkdf(
        seed_phrase=args.seed_phrase, 
        dice_rolls=args.dice_rolls, 
        additional_seed=args.additional_seed
    )
    
    # 2. Direct Mnemonic Generation
    final_phrase = generate_bip39_phrase(pure_entropy)
    entropy_hex_str = binascii.hexlify(pure_entropy).decode('ascii')
    
    # 3. Formatted Terminal Report Output
    print("\n" + "="*70)
    print(f"🔒 UNIFORM MASTER ENTROPY HEX (32-bytes):")
    print(f"{entropy_hex_str}")
    print("-"*70)
    print("📋 FINAL COMPLETED 24-WORD RECOVERY STRING:")
    print(f"\n{final_phrase}\n")
    print("="*70)

if __name__ == "__main__":
    main()
