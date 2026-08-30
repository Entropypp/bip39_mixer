#!/usr/bin/env python3
import sys
import argparse
import hashlib
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

def calculate_mix(seed_phrase: str, dice_rolls: str = None, additional_seed: str = None) -> bytes:
    """
    Chronologically hashes inputs directly into a standard SHA-256 context.
    Returns raw intermediate bytes for key stretching.
    """
    h_ctx = hashlib.sha256()
    words = clean_word_list(seed_phrase)
    
    # Process Base Phrase state sequence
    if words:
        print(f"[*] Processing base seed phrase ({len(words)} words)...")
        for word in words:
            word_idx = word_to_index(word)
            h_ctx.update(struct.pack(">H", word_idx))
            h_ctx.update(word.encode('utf-8'))
            
    # Specification 1: Concatenated Dice Roll string mixing
    if dice_rolls:
        print(f"[*] Mixing dice data sequence: '{dice_rolls}'")
        for roll in dice_rolls:
            if roll not in "123456":
                print(f"[!] Error: Character '{roll}' is not a valid 1-6 die value.")
                sys.exit(1)
            h_ctx.update(roll.encode('utf-8'))
            
    # Specification 2: Additional Seed Phrase processing
    if additional_seed:
        extra_words = clean_word_list(additional_seed)
        print(f"[*] Mixing additional seed sequence ({len(extra_words)} words)...")
        for word in extra_words:
            word_idx = word_to_index(word)
            h_ctx.update(struct.pack(">H", word_idx))
            h_ctx.update(word.encode('utf-8'))

    return h_ctx.digest()

def stretch_and_generate_phrase(raw_entropy: bytes) -> tuple:
    """
    Applies PBKDF2 key stretching and converts the output into a complete
    24-word BIP-39 recovery phrase sentence.
    """
    print("[*] Applying PBKDF2 stretching loop (2048 iterations)...")
    
    # 1. PBKDF2 stretching using HMAC-SHA256 (yielding 32 bytes / 256 bits)
    stretched_entropy = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=raw_entropy,
        salt=b"universal_mixer_salt",
        iterations=2048,
        dklen=32  
    )
    
    # 2. Complete 24-word generation via the standard library.
    # This automatically splits the 256 bits into 11-bit chunks, appends the
    # 8-bit checksum, and joins them into a single string.
    complete_phrase = mnemo.to_mnemonic(stretched_entropy)
    
    return stretched_entropy, complete_phrase

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

    # 1. Core Mixing Execution
    raw_entropy = calculate_mix(
        seed_phrase=args.seed_phrase, 
        dice_rolls=args.dice_rolls, 
        additional_seed=args.additional_seed
    )
    
    # 2. Stretching and Full Mnemonic Conversion
    stretched_bytes, final_phrase = stretch_and_generate_phrase(raw_entropy)
    final_hex_str = binascii.hexlify(stretched_bytes).decode('ascii')
    
    # 3. Formatted Terminal Report Output
    print("\n" + "="*70)
    print(f"🔒 STRETCHED MASTER ENTROPY HEX (32-bytes):")
    print(f"{final_hex_str}")
    print("-"*70)
    print("📋 FINAL COMPLETED 24-WORD RECOVERY STRING:")
    print(f"\n{final_phrase}\n")
    print("="*70)

if __name__ == "__main__":
    main()
