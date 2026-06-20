# 🔐 COMPLETE HNP ANALYSIS TOOL

<div align="center">

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-ECDSA-orange.svg)](https://bitcoin.org/)
[![SageMath](https://img.shields.io/badge/SageMath-LLL-green.svg)](https://www.sagemath.org/)

**Kompleksowe narzędzie do wykrywania podatności HNP (Hidden Number Problem) w podpisach Bitcoin**

</div>

---

## 📋 SPIS TREŚCI

- [🇬🇧 English Version](#english-version)
- [🇷🇺 Русская версия](#русская-версия)

---

## 🇬🇧 ENGLISH VERSION

### 🎯 Overview

This tool performs **comprehensive security analysis** of Bitcoin ECDSA signatures to detect cryptographic vulnerabilities, particularly the **Hidden Number Problem (HNP)** that can lead to private key recovery.

### ⚠️ DISCLAIMER

> **THIS TOOL IS FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY!**
> 
> - Do not use on addresses you do not own
> - The recovered private keys are REAL and can compromise funds
> - Always use secure, cryptographically strong random number generators
> - This is a vulnerability demonstration tool, not a hacking tool

### ✨ Features

| Test | Description | Criticality |
|------|-------------|-------------|
| **Reused Nonce** | Detects identical `r` values → **IMMEDIATE PRIVATE KEY RECOVERY** | 🔴 CRITICAL |
| **Dark Skippy** | Detects watermark patterns in nonces | 🟠 HIGH |
| **LSB Bias** | Chi-square test for bit leakage in `r` values | 🟠 HIGH |
| **Bit Length Bias** | Analyzes distribution of bit lengths | 🟡 MEDIUM |
| **Autocorrelation** | Correlation analysis of sequential `r` values | 🟡 MEDIUM |
| **R Distances** | Analyzes differences between consecutive `r` values | 🟡 MEDIUM |
| **Serial Correlation** | Pearson correlation test for `r` values | 🟡 MEDIUM |
| **Weak RNG** | Entropy analysis with Monte Carlo simulation | 🟠 HIGH |
| **Low-S Check** | BIP-0062 low-s normalization verification | 🟢 LOW |
| **Sage/LLL Export** | Generates HNP equation files for lattice attacks | 📤 EXPORT |

### 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hnp-analysis.git
cd hnp-analysis

# Install dependencies
pip install -r requirements.txt

# Requirements:
# - Python 3.8+
# - tqdm
# - (Optional) SageMath for lattice attacks

python nowapodatnosc.py transactions.txt
Input File Format
The tool accepts transaction data in the following format:
txid: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
pubkey: 04b0bd634234abbb1ba1e986e8841c...
r: 00d47b1334b3a1f8c9b8e2c8d2e3f4a5...
s: 001a2b3c4d5e6f7a8b9c0d1e2f3a4b5c...
z: 00e3b0c44298fc1c149afbf4c8996fb9...
sighash: ALL
---------------------------------------------
txid: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
pubkey: 04b0bd634234abbb1ba1e986e8841c...
r: 00d47b1334b3a1f8c9b8e2c8d2e3f4a5...
s: 001a2b3c4d5e6f7a8b9c0d1e2f3a4b5c...
z: 00e3b0c44298fc1c149afbf4c8996fb9...
sighash: ALL

# 🔍 BITCOIN TRANSACTION EXTRACTOR & SIGNATURE PARSER

<div align="center">

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-ECDSA-orange.svg)](https://bitcoin.org/)
[![SegWit](https://img.shields.io/badge/SegWit-BIP141-green.svg)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
[![Taproot](https://img.shields.io/badge/Taproot-BIP341-purple.svg)](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

**Zaawansowane narzędzie do ekstrakcji podpisów ECDSA z transakcji Bitcoin**
**Advanced tool for extracting ECDSA signatures from Bitcoin transactions**

</div>

---

## 📋 SPIS TREŚCI / TABLE OF CONTENTS

- [🇬🇧 English Version](#english-version)
- [🇷🇺 Русская версия](#русская-версия)
- [🇵🇱 Polska wersja](#polska-wersja)

---

## 🇬🇧 ENGLISH VERSION

### 🎯 Overview

This tool extracts **ECDSA signatures** from Bitcoin transactions, supporting **all major address types** including Legacy (P2PKH), SegWit (P2WPKH, P2WSH), Nested SegWit (P2SH-P2WPKH), and **Taproot (P2TR)**.

### ⚠️ DISCLAIMER

> **THIS TOOL IS FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY!**
>
> - Only use on transactions you own or have permission to analyze
> - The extracted signatures can potentially lead to private key recovery if nonces are reused
> - This is a vulnerability demonstration tool, not a hacking tool
> - Always use secure, cryptographically strong random number generators

### ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Multiple Address Types** | P2PKH (1...), P2SH (3...), P2WPKH (bc1...), P2WSH, P2TR | ✅ |
| **SegWit Support** | Full BIP143 implementation for correct `z` calculation | ✅ |
| **Taproot Support** | BIP341 P2TR signature extraction | ✅ |
| **Multi-Signature** | P2SH multisig and P2WSH multisig detection | ✅ |
| **Multiple APIs** | 5 different blockchain explorers with rotation | ✅ |
| **User-Agent Rotation** | 16+ different user agents to avoid rate limiting | ✅ |
| **Resume Support** | Saves last processed TXID for continuation | ✅ |
| **Error Handling** | Automatic API failover with retry limits | ✅ |
| **All SIGHASH Types** | ALL, NONE, SINGLE, ANYONECANPAY variants | ✅ |

### 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bitcoin-signature-extractor.git
cd bitcoin-signature-extractor

# Install dependencies
pip install -r requirements.txt

# Requirements:
# - Python 3.8+
# - requests
# - ecdsa
# - base58
📖 Usage
1. Prepare TXID List
Create a file txids.txt with one transaction ID per line:

txt
4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
d5d3ef5d8e9a1c2b3f4e5d6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c
2. Run the Extractor
bash
python wyciaganiersz.py
3. Output Format
The tool generates a signatures.txt file with the following format:

text
txid: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
pubkey: 04b0bd634234abbb1ba1e986e8841c...
r: 00d47b1334b3a1f8c9b8e2c8d2e3f4a5...
s: 001a2b3c4d5e6f7a8b9c0d1e2f3a4b5c...
z: 00e3b0c44298fc1c149afbf4c8996fb9...
sighash: ALL
----------------------------------
📊 Supported Address Types
Type	Format	Example	Status
P2PKH	1...	1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa	✅ Full
P2SH	3...	3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy	✅ Full
P2WPKH	bc1q...	bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq	✅ Full
P2WSH	bc1q... (multisig)	bc1q...	✅ Full
P2TR	bc1p...	bc1p...	✅ Full
# 📦 BITCOIN BLOCK TRANSACTION EXTRACTOR

<div align="center">

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-Blockchain-orange.svg)](https://bitcoin.org/)
[![API](https://img.shields.io/badge/API-Multiple-green.svg)](https://blockchair.com/)

**Zaawansowane narzędzie do pobierania transakcji z bloków Bitcoin**
**Advanced tool for fetching transactions from Bitcoin blocks**

</div>

---

## 📋 SPIS TREŚCI / TABLE OF CONTENTS

- [🇬🇧 English Version](#english-version)
- [🇷🇺 Русская версия](#русская-версия)
- [🇵🇱 Polska wersja](#polska-wersja)

---

## 🇬🇧 ENGLISH VERSION

### 🎯 Overview

This tool fetches **all transaction IDs (TXIDs)** from Bitcoin blocks using **multiple blockchain APIs** with automatic failover. It supports resume functionality, API rotation, and comprehensive error handling.

### ⚠️ DISCLAIMER

> **THIS TOOL IS FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY!**
>
> - Respect API rate limits
> - Do not overload the APIs
> - Use responsibly and ethically
> - This is a data collection tool, not a hacking tool

### ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Multiple APIs** | 4 different blockchain explorers with automatic failover | ✅ |
| **Resume Support** | Continues from last processed block | ✅ |
| **User-Agent Rotation** | 3+ different user agents for rate limit avoidance | ✅ |
| **Error Recovery** | Automatic API switching after 3 failures | ✅ |
| **Block Range Processing** | Process blocks from start to end block | ✅ |
| **Rate Limiting** | 1-second delay between requests | ✅ |
| **Output Storage** | All TXIDs saved to `txids.txt` | ✅ |
| **Progress Tracking** | Last block saved to `last_block.txt` | ✅ |

### 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bitcoin-block-extractor.git
cd bitcoin-block-extractor

# Install dependencies
pip install -r requirements.txt

# Requirements:
# - Python 3.8+
# - requests

📖 Usage
Basic Usage
bash
python wczytywanieblokowpoprawione.py
Configuration
The tool uses the following default settings:

python
DEFAULT_START_BLOCK = 1        # Genesis block
END_BLOCK = 1000000           # Can be modified as needed
DELAY_BETWEEN_REQUESTS = 1    # Seconds
MAX_FAILURES_BEFORE_SWITCH = 3
Input/Output Files
File	Description
txids.txt	All fetched transaction IDs
last_block.txt	Last processed block number (for resume)
📊 API Configuration
The tool uses four different APIs with automatic rotation:

python
API_URLS = [
    'https://api.blockchair.com/bitcoin/raw/block/{block_height}',      # Primary
    'https://blockchain.info/rawblock/{block_height}',                  # Backup
    'https://blockstream.info/api/block-height/{block_height}',         # Fast
    'https://mempool.space/api/block-height/{block_height}'             # Alternative
]
🔧 Technical Implementation
Block Processing Flow
API Selection: Tests all APIs to find a working one

Block Fetching: Retrieves block data at specified height

TXID Extraction: Parses block structure to extract transaction IDs

Storage: Appends TXIDs to txids.txt

Progress Save: Updates last_block.txt

Error Handling: Switches API on repeated failures

DONATE: bc1qps62cyk9f9unmdkc9k3ccj9e2h8ywfhg2j53ec

Built with ❤️ for the crypto research community.
