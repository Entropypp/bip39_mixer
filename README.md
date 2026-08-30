# Universal Secure Entropy Mixer & BIP-39 Phrase Generator

A clean, standalone Python Command Line Interface (CLI) utility that securely aggregates user-supplied entropy sources (existing seed phrases, additional seed words, and physical dice rolls) to generate a fully compliant 24-word BIP-39 recovery mnemonic sentence.

This tool adapts core cryptographic mechanics into a generic script running entirely on a regular PC with zero platform-specific dependencies. 

The primary purpose of this tool is to leverage high-quality hardware entropy (HWW) from existing seed phrases and mathematically bind it with secondary local entropy sources to derive an independent master pool.

---

## ⚙️ How It Works

1. **Domain-Separated Aggregation**: To prevent length-extension and collision vulnerabilities, inputs are chronologically structured using distinct byte boundaries (e.g., `[BASE_SEED_START]` and `[BASE_SEED_END]`). Raw strings, numerical paths, and 11-bit BIP-39 indexes (`struct.pack(">H")`) are cleanly isolated within the streaming context.
2. **Cryptographic Extraction via HMAC-SHA256**: The redundant latency loops of PBKDF2 are removed. Because your hardware and physical inputs already yield high entropy, the script uses an **HKDF-Extract** methodology via a fixed-salt HMAC-SHA256 wrapper. This compresses variable-length, unevenly distributed user sequences into a uniform, unstretchable 256-bit entropy pool.
3. **BIP-39 Mnemonic Formatting**: The extracted 32-byte (256-bit) entropy pool is passed directly to the standard library framework. The script automatically appends the standard 8-bit SHA-256 checksum, divides the consolidated 264 bits into 24 distinct 11-bit chunks, and prints the finalized phrase sentence.

---

## 🚀 Installation & Prerequisites

This tool requires **Python 3.6+** and the official Python `mnemonic` package.

1. **Save the script** as `bip39_mixer.py` on your computer.
2. **Install the dependencies** via your terminal:
   ```bash
   pip install mnemonic
   ```

---

## 📋 Command Usage & Parameters

The script exposes three arguments via the command line. You can mix and match parameters depending on your deployment scenario:

| Parameter | Type | Required? | Description |
| :--- | :--- | :--- | :--- |
| `--seed_phrase` | `string` | Optional* | Base seed phrase. Accepts comma-delimited or space-delimited words. |
| `--dice_rolls` | `string` | Optional* | A concatenated string of raw numbers (`1` through `6`) representing physical die rolls. |
| `--additional_seed` | `string` | Optional | Extra seed words to append/mix sequentially into the existing tracking context. |

*\*Note: You must supply at least one input source (`--seed_phrase` or `--dice_rolls`) to initiate the engine execution.*

---

## 💡 Practical Examples

### 1. Extend an Existing Seed Phrase with Physical Dice Rolls
Combine a small phrase set or an existing backup directly with a fresh sequence of manual dice rolls:
```bash
python3 bip39_mixer.py --seed_phrase "gravity, luxury, visual" --dice_rolls "61524361"
```

### 2. Mix Two Independent Seed Phrases
Blend two distinct phrase blocks together chronologically to construct a brand new combined seed:
```bash
python3 bip39_mixer.py --seed_phrase "abandon ability able" --additional_seed "solar toggle vintage"
```

### 3. Generate a Seed from Pure Dice Rolls Only
Create a highly secure, completely random wallet without using any computer or mobile app RNG:
```bash
python3 bip39_mixer.py --dice_rolls "55123461254316223145612456"
```

---

## 🔒 Security Best Practices for PC Execution
**This script was designed as a Proof of Concept (PoC) only. Use at your own risk!**

Because this script runs inside a desktop terminal instead of an isolated hardware secure element, observe the following absolute safety rules:
* **Air-gapped Environment**: For live production wallets, execute this script strictly on a clean, amnesic live-boot operating system (like TAILS) with all Wi-Fi, Bluetooth, and internet adapters entirely disconnected.
* **Terminal Scrubbing**: Terminal windows cache history logs. After completing generation runs, fully flush or clear your terminal environment memory logs via commands like `history -c` or `clear` to prevent residual command parameters from resting in text configurations on your local disk.
* **No Clipboard/Screenshots**: Do not copy-paste sensitive inputs or outputs using standard clipboard commands. Local monitoring software, spyware, or background scripts can access temporary operating system clipboards easily.

---

## ⚖️ License & Compatibility

This tool relies exclusively on public-domain, industry-wide internet standards (**RFC 5869 / HKDF**, **FIPS 180-4**, and **Bitcoin BIP-39**). Because it has been entirely stripped of proprietary firmware files, UI hooks, and vendor-specific configuration tags, it serves as an open-source standalone software utility. 

Feel free to remix, adjust, and distribute this script under open-source software license conventions (such as MIT or GPLv3).
