import requests
import hashlib
import struct
import time
import random
from ecdsa import util, SECP256k1
from collections import defaultdict
from base58 import b58encode_check
import os
import sys
import binascii
import io

RAW_TX_APIS = [
    "https://blockstream.info/api/tx/{}/hex",
    "https://blockchain.info/rawtx/{}?format=hex",
    "https://api.blockcypher.com/v1/btc/main/txs/{}?includeHex=true",
    "https://sochain.com/api/v2/tx/BTC/{}",
    "https://mempool.space/api/tx/{}/hex",
]

# ============================================================
# 15+ RÓŻNYCH USER-AGENTÓW DLA LEPSZEJ ROTACJI
# ============================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 OPR/103.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
]

DELAY_BETWEEN_TX = 3
TXID_FILE = "txids.txt"
SIGNATURES_FILE = "signatures.txt"
LAST_TXID_FILE = "last_txid.txt"
api_failures = defaultdict(int)
MAX_API_FAILURES = 10

# ============================================================
# BECH32 - PEŁNA POPRAWNA IMPLEMENTACJA (BIP173)
# ============================================================
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_encode(hrp, version, program):
    if version < 0 or version > 16:
        return None
    if len(program) < 2 or len(program) > 40:
        return None
    if version == 0 and len(program) not in [20, 32]:
        return None
    
    five_bit_data = convertbits(program, 8, 5, True)
    if five_bit_data is None:
        return None
    
    data = [version] + five_bit_data
    checksum = bech32_create_checksum(hrp, data)
    combined = data + checksum
    address = hrp + "1" + "".join(BECH32_ALPHABET[x] for x in combined)
    return address

# ============================================================
# FUNKCJE HASH
# ============================================================
def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# ============================================================
# PARSOWANIE SCRIPT
# ============================================================
OP_N_MAPPING = {
    0x00: 0, 0x51: 1, 0x52: 2, 0x53: 3, 0x54: 4, 0x55: 5,
    0x56: 6, 0x57: 7, 0x58: 8, 0x59: 9, 0x5a: 10, 0x5b: 11,
    0x5c: 12, 0x5d: 13, 0x5e: 14, 0x5f: 15, 0x60: 16
}
OP_CHECKMULTISIG = 0xAE
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_0 = 0x00

def decode_script(script_hex):
    try:
        script_bytes = bytes.fromhex(script_hex)
    except ValueError:
        return None
    if not script_bytes:
        return []
    i = 0
    parsed_script = []
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if 0x01 <= opcode <= 0x4B:
            data_len = opcode
            if i + data_len > len(script_bytes):
                return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4C:
            if i + 1 > len(script_bytes): return None
            data_len = script_bytes[i]
            i += 1
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4D:
            if i + 2 > len(script_bytes): return None
            data_len = int.from_bytes(script_bytes[i : i + 2], 'little')
            i += 2
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4E:
            if i + 4 > len(script_bytes): return None
            data_len = int.from_bytes(script_bytes[i : i + 4], 'little')
            i += 4
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        else:
            parsed_script.append(opcode)
    return parsed_script

def is_compressed_pubkey(pubkey_hex):
    if not pubkey_hex or len(pubkey_hex) < 2:
        return False
    return pubkey_hex[:2] in ('02', '03', '04')

def extract_pubkeys_from_script(decoded_script):
    pubkeys = []
    for item in decoded_script:
        if isinstance(item, str) and ((len(item) == 66 and item[:2] in ('02', '03')) or (len(item) == 130 and item[:2] == '04')):
            pubkeys.append(item)
    return pubkeys

def is_der_signature(data_hex):
    if not data_hex or len(data_hex) < 10:
        return False
    try:
        data = bytes.fromhex(data_hex)
        if not data or data[0] != 0x30:
            return False
        if data[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            sig_to_check = data[:-1]
        else:
            sig_to_check = data
        r, s = util.sigdecode_der(sig_to_check, SECP256k1.order)
        return True
    except:
        return False

def find_all_der_signatures(witness_items):
    signatures = []
    for item in witness_items:
        if item and is_der_signature(item):
            signatures.append(item)
    return signatures

# ============================================================
# FUNKCJE KONWERSJI ADRESÓW
# ============================================================
def pubkey_to_address(pubkey_bytes):
    pubkey_hash = hash160(pubkey_bytes)
    prefix = b"\x00" + pubkey_hash
    return b58encode_check(prefix).decode()

def pubkey_to_address_p2sh_p2wpkh(pubkey_bytes):
    pubkey_hash = hash160(pubkey_bytes)
    redeem_script = b'\x00\x14' + pubkey_hash
    script_hash = hash160(redeem_script)
    prefix = b"\x05" + script_hash
    return b58encode_check(prefix).decode()

def pubkey_to_address_p2wpkh(pubkey_bytes):
    pubkey_hash = hash160(pubkey_bytes)
    return bech32_encode('bc', 0, pubkey_hash)

def witness_script_to_address_p2wsh(witness_script_hex):
    witness_script_bytes = bytes.fromhex(witness_script_hex)
    script_sha256 = hashlib.sha256(witness_script_bytes).digest()
    return bech32_encode('bc', 0, script_sha256)

def redeem_script_to_address_p2sh(redeem_script_hex):
    redeem_script_bytes = bytes.fromhex(redeem_script_hex)
    script_hash = hash160(redeem_script_bytes)
    prefix = b"\x05" + script_hash
    return b58encode_check(prefix).decode()

# ============================================================
# POPRAWIONA FUNKCJA - DODANO P2TR (TAPROOT)
# ============================================================
def get_script_type_from_utxo(utxo_script_hex):
    if not utxo_script_hex:
        return 'UNKNOWN'
    try:
        script_bytes = bytes.fromhex(utxo_script_hex)
        # P2PKH: 76 A9 14 <20 bytes> 88 AC
        if len(script_bytes) == 25 and script_bytes[0] == OP_DUP and script_bytes[1] == OP_HASH160 and script_bytes[2] == 0x14 and script_bytes[-2:] == b'\x88\xac':
            return 'P2PKH'
        # P2SH: A9 14 <20 bytes> 87
        elif len(script_bytes) == 23 and script_bytes[0] == OP_HASH160 and script_bytes[1] == 0x14 and script_bytes[-1] == 0x87:
            return 'P2SH'
        # P2WPKH: 00 14 <20 bytes>
        elif len(script_bytes) == 22 and script_bytes[0] == OP_0 and script_bytes[1] == 0x14:
            return 'P2WPKH'
        # P2WSH: 00 20 <32 bytes>
        elif len(script_bytes) == 34 and script_bytes[0] == OP_0 and script_bytes[1] == 0x20:
            return 'P2WSH'
        # DODANE: P2TR (Taproot) - 51 20 <32 bytes>
        elif len(script_bytes) == 34 and script_bytes[0] == 0x51 and script_bytes[1] == 0x20:
            return 'P2TR'
        else:
            return 'OTHER'
    except:
        return 'UNKNOWN'

def get_p2wpkh_scriptcode(pubkey_hash):
    return b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

# ============================================================
# POPRAWIONE FUNKCJE DO OBLICZANIA z
# ============================================================
def read_varint_from_bytes(data, offset):
    prefix = data[offset]
    offset += 1
    if prefix < 0xfd:
        return prefix, offset
    elif prefix == 0xfd:
        val = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2
        return val, offset
    elif prefix == 0xfe:
        val = int.from_bytes(data[offset:offset + 4], 'little')
        offset += 4
        return val, offset
    val = int.from_bytes(data[offset:offset + 8], 'little')
    offset += 8
    return val, offset

def serialize_script_for_sighash(script_bytes):
    result = b""
    if len(script_bytes) < 0xfd:
        result += bytes([len(script_bytes)])
    elif len(script_bytes) <= 0xffff:
        result += b'\xfd' + struct.pack('<H', len(script_bytes))
    elif len(script_bytes) <= 0xffffffff:
        result += b'\xfe' + struct.pack('<I', len(script_bytes))
    else:
        result += b'\xff' + struct.pack('<Q', len(script_bytes))
    result += script_bytes
    return result

def parse_transaction_for_sighash(raw_tx_hex):
    """
    Parsuje transakcję - ZACHOWUJE ORYGINALNE BAJTY TXID (bez odwracania)
    """
    data = bytes.fromhex(raw_tx_hex)
    offset = 0
    
    version = int.from_bytes(data[offset:offset + 4], 'little')
    offset += 4
    
    is_segwit = False
    if offset < len(data) and data[offset] == 0x00:
        if offset + 1 < len(data) and data[offset + 1] == 0x01:
            is_segwit = True
            offset += 2
    
    vin_count, offset = read_varint_from_bytes(data, offset)
    inputs = []
    for _ in range(vin_count):
        # NIE odwracamy TXID - zachowujemy little-endian
        txid = data[offset:offset + 32]
        offset += 32
        vout = int.from_bytes(data[offset:offset + 4], 'little')
        offset += 4
        script_len, offset = read_varint_from_bytes(data, offset)
        script_sig = data[offset:offset + script_len]
        offset += script_len
        sequence = int.from_bytes(data[offset:offset + 4], 'little')
        offset += 4
        inputs.append({
            'txid': txid,
            'vout': vout,
            'script_sig': script_sig,
            'sequence': sequence
        })
    
    vout_count, offset = read_varint_from_bytes(data, offset)
    outputs = []
    for _ in range(vout_count):
        value = int.from_bytes(data[offset:offset + 8], 'little')
        offset += 8
        script_len, offset = read_varint_from_bytes(data, offset)
        script_pubkey = data[offset:offset + script_len]
        offset += script_len
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    
    witnesses = []
    if is_segwit:
        for _ in range(vin_count):
            witness_items = []
            witness_count, offset = read_varint_from_bytes(data, offset)
            for _ in range(witness_count):
                item_len, offset = read_varint_from_bytes(data, offset)
                witness_items.append(data[offset:offset + item_len])
                offset += item_len
            witnesses.append(witness_items)
    
    locktime = int.from_bytes(data[offset:offset + 4], 'little')
    
    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'witnesses': witnesses,
        'locktime': locktime,
        'is_segwit': is_segwit,
        'vin_count': vin_count,
        'vout_count': vout_count
    }

def zdekoduj_transakcje(raw_tx_hex):
    """Alias dla parse_transaction_for_sighash"""
    return parse_transaction_for_sighash(raw_tx_hex)

def get_sighash_z_segwit(txid, input_index, raw_tx_hex, script_code_hex, utxo_value, sighash_type=0x01):
    """
    Oblicza z (sighash) dla SegWit według BIP143
    NIE odwraca TXID - używa surowych bajtów z serializacji
    """
    try:
        tx = parse_transaction_for_sighash(raw_tx_hex)
        
        if input_index >= len(tx['inputs']):
            return None, "ERROR: input_index out of range"
        
        current_input = tx['inputs'][input_index]
        
        hash_type = sighash_type & 0x1f
        is_anyone_can_pay = (sighash_type & 0x80) != 0
        
        # hash_prevouts - używamy ORYGINALNYCH bajtów TXID
        if not is_anyone_can_pay:
            prevouts_data = b''.join(inp['txid'] + struct.pack('<I', inp['vout']) for inp in tx['inputs'])
            hash_prevouts = double_sha256(prevouts_data)
        else:
            hash_prevouts = b'\x00' * 32
        
        # hash_sequence
        if not is_anyone_can_pay and hash_type != 0x02 and hash_type != 0x03:
            seq_data = b''.join(struct.pack('<I', inp['sequence']) for inp in tx['inputs'])
            hash_sequence = double_sha256(seq_data)
        else:
            hash_sequence = b'\x00' * 32
        
        # hash_outputs
        if hash_type == 0x01:
            outputs_data = b""
            for out in tx['outputs']:
                outputs_data += struct.pack('<Q', out['value'])
                outputs_data += serialize_script_for_sighash(out['script_pubkey'])
            hash_outputs = double_sha256(outputs_data)
        elif hash_type == 0x03:
            if input_index < len(tx['outputs']):
                single_output = tx['outputs'][input_index]
                outputs_data = struct.pack('<Q', single_output['value'])
                outputs_data += serialize_script_for_sighash(single_output['script_pubkey'])
                hash_outputs = double_sha256(outputs_data)
            else:
                hash_outputs = b'\x00' * 32
        else:
            hash_outputs = b'\x00' * 32
        
        script_code = bytes.fromhex(script_code_hex)
        
        # Preimage - używamy ORYGINALNYCH bajtów TXID
        preimage = b""
        preimage += struct.pack('<I', tx['version'])
        preimage += hash_prevouts
        preimage += hash_sequence
        preimage += current_input['txid']
        preimage += struct.pack('<I', current_input['vout'])
        preimage += serialize_script_for_sighash(script_code)
        preimage += struct.pack('<Q', utxo_value)
        preimage += struct.pack('<I', current_input['sequence'])
        preimage += hash_outputs
        preimage += struct.pack('<I', tx['locktime'])
        preimage += struct.pack('<I', sighash_type)
        
        z = int.from_bytes(double_sha256(preimage), 'big')
        return z, "ACCURATE"
        
    except Exception as e:
        print(f"⚠️ Błąd obliczania z dla SegWit: {e}")
        return None, "ERROR"

def get_sighash_z_legacy(txid, input_index, raw_tx_hex, script_code_hex, utxo_value, sighash_type=0x01):
    """Oblicza z dla Legacy (P2PKH, P2SH)"""
    try:
        tx = parse_transaction_for_sighash(raw_tx_hex)
        
        if input_index >= len(tx['inputs']):
            return None, "ERROR: input_index out of range"
        
        hash_type = sighash_type & 0x1f
        is_anyone_can_pay = (sighash_type & 0x80) != 0
        
        version = struct.pack("<I", tx['version'])
        locktime = struct.pack("<I", tx['locktime'])
        input_count = encode_varint(tx['vin_count'])
        
        inputs_data = b""
        for j, v in enumerate(tx['inputs']):
            if is_anyone_can_pay and j != input_index:
                continue
            inputs_data += v['txid']
            inputs_data += struct.pack("<I", v['vout'])
            if j == input_index:
                inputs_data += serialize_script_for_sighash(bytes.fromhex(script_code_hex))
            else:
                inputs_data += encode_varint(0)
            inputs_data += struct.pack("<I", v['sequence'])
        
        if hash_type == 0x01:
            outputs_data = b""
            for o in tx['outputs']:
                outputs_data += struct.pack("<Q", o['value'])
                outputs_data += serialize_script_for_sighash(o['script_pubkey'])
        elif hash_type == 0x03:
            if input_index < len(tx['outputs']):
                single_output = tx['outputs'][input_index]
                outputs_data = struct.pack("<Q", single_output['value'])
                outputs_data += serialize_script_for_sighash(single_output['script_pubkey'])
            else:
                outputs_data = b""
        else:
            outputs_data = b""
        
        output_count = encode_varint(len(tx['outputs']) if hash_type == 0x01 else (input_index + 1 if hash_type == 0x03 else 0))
        
        preimage = version + input_count + inputs_data + output_count + outputs_data + locktime + struct.pack("<I", sighash_type)
        z = int.from_bytes(sha256d(preimage), 'big')
        return z, "ACCURATE"
        
    except Exception as e:
        print(f"⚠️ Błąd obliczania z dla Legacy: {e}")
        return None, "ERROR"

# ============================================================
# FUNKCJE API - POPRAWIONE!
# ============================================================
def get_headers():
    """Zwraca losowy User-Agent z 15+ różnych"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a", encoding="utf-8") as f:
        f.write(linia + "\n")

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', i)
    return b'\xff' + struct.pack('<Q', i)

def parse_pushdata(script_bytes):
    items = []
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if opcode <= 75:
            items.append(script_bytes[i:i + opcode])
            i += opcode
        elif opcode == 76:
            length = script_bytes[i]
            i += 1
            items.append(script_bytes[i:i + length])
            i += length
        elif opcode == 77:
            length = int.from_bytes(script_bytes[i:i + 2], 'little')
            i += 2
            items.append(script_bytes[i:i + length])
            i += length
        else:
            items.append(bytes([opcode]))
    return items

def fetch_raw_tx(txid):
    """Pobiera surowy hex transakcji z rotacją API i User-Agent - BEZ DŁUGICH PRZERW!"""
    for api in RAW_TX_APIS:
        if api_failures[api] >= MAX_API_FAILURES:
            print(f"⛔ API {api} tymczasowo wyłączone (błędy: {api_failures[api]})")
            continue
            
        try:
            url = api.format(txid)
            headers = get_headers()
            print(f"🌐 Próbuję pobrać TX z API: {url}")
            
            r = requests.get(url, headers=headers, timeout=10)  # timeout skrócony do 10s
            
            if r.status_code == 200:
                raw = r.text.strip()
                if raw and all(c in "0123456789abcdefABCDEF" for c in raw):
                    api_failures[api] = 0
                    print(f"✅ Pobrano hex ({len(raw)} znaków)")
                    return raw
                else:
                    print(f"⚠️ API {api} zwróciło niepoprawny format")
                    api_failures[api] += 1
                    
            elif r.status_code == 404:
                print(f"ℹ️ TXID {txid} nie istnieje (404)")
                return None
                
            elif r.status_code == 429:
                print(f"⏳ Rate limit - czekam 2s...")
                time.sleep(2)  # ZAMIast 60!
                api_failures[api] += 1
                
            elif r.status_code == 403:
                print(f"🚫 API {api} zablokowało dostęp (403) - czekam 3s")
                time.sleep(3)  # ZAMIast 120!
                api_failures[api] += 1
                
            else:
                print(f"❌ API {api} zwróciło błąd {r.status_code}")
                api_failures[api] += 1
                
        except requests.exceptions.Timeout:
            print(f"⏰ Timeout dla API {api}")
            api_failures[api] += 1
            
        except requests.exceptions.ConnectionError:
            print(f"🔌 Błąd połączenia dla API {api}")
            api_failures[api] += 1
            
        except Exception as e:
            print(f"❌ Błąd API: {api} -> {e}")
            api_failures[api] += 1
            
        time.sleep(random.uniform(0.2, 0.5))  # skrócone
    
    print(f"❌ Nie udało się pobrać TXID: {txid}")
    return None

def print_api_status():
    """Wyświetla status wszystkich API"""
    print("\n📊 Status API:")
    for api, failures in api_failures.items():
        if failures >= MAX_API_FAILURES:
            print(f"  {api}: ⛔ Zablokowane (błędy: {failures}/{MAX_API_FAILURES})")
        else:
            print(f"  {api}: ✅ Działa (błędy: {failures}/{MAX_API_FAILURES})")

# ============================================================
# PROCESOWANIE TRANSAKCJI - DODANO OBSŁUGĘ TAPROOT (P2TR)
# ============================================================
def process_transaction(txid):
    print(f"\n🔍 Analizuję TXID: {txid}")
    raw_tx = fetch_raw_tx(txid)
    if not raw_tx:
        return
    try:
        tx = zdekoduj_transakcje(raw_tx)
    except Exception as e:
        print(f"❌ Błąd dekodowania: {e}")
        return

    # ============================================================
    # 1. OBSŁUGA WITNESS (bc1 - P2WPKH, P2WSH multisig, P2TR Taproot)
    # ============================================================
    if tx.get('is_segwit', False) and tx.get('witnesses'):
        for idx, witness in enumerate(tx['witnesses']):
            if not witness:
                continue
            
            # POPRAWA: odwróć TXID dla API!
            prev_txid_bytes = tx['inputs'][idx]['txid']
            prev_txid = prev_txid_bytes[::-1].hex()
            prev_vout = tx['inputs'][idx]['vout']
            utxo_script = None
            utxo_value = 0
            utxo_type = 'UNKNOWN'
            
            print(f"🔍 Pobieram UTXO: {prev_txid}:{prev_vout}")
            utxo_raw = fetch_raw_tx(prev_txid)
            if utxo_raw:
                print(f"✅ Pobrano UTXO ({len(utxo_raw)} bajtów)")
                utxo_tx = parse_transaction_for_sighash(utxo_raw)
                if prev_vout < len(utxo_tx['outputs']):
                    utxo_script = utxo_tx['outputs'][prev_vout]['script_pubkey'].hex()
                    utxo_value = utxo_tx['outputs'][prev_vout]['value']
                    utxo_type = get_script_type_from_utxo(utxo_script)
                    print(f"📌 UTXO type: {utxo_type}, value: {utxo_value}")
                else:
                    print(f"⚠️ Vout {prev_vout} nie istnieje w UTXO")
            else:
                print(f"❌ Nie udało się pobrać UTXO dla {prev_txid}")
            
            witness_hex = [item.hex() for item in witness]
            
            # P2WPKH
            if len(witness) == 2 and utxo_type == 'P2WPKH':
                try:
                    sig_hex = witness_hex[0]
                    pubkey_hex = witness_hex[1]
                    
                    if not pubkey_hex or not is_compressed_pubkey(pubkey_hex):
                        continue
                    
                    sig_bytes = bytes.fromhex(sig_hex)
                    sighash_type = 0x01
                    if sig_bytes and sig_bytes[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                        sighash_type = sig_bytes[-1]
                        der_sig = sig_bytes[:-1]
                    else:
                        der_sig = sig_bytes
                    
                    r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                    pubkey = bytes.fromhex(pubkey_hex)
                    pubkey_hash = hash160(pubkey)
                    
                    address = pubkey_to_address_p2wpkh(pubkey)
                    script_code_hex = get_p2wpkh_scriptcode(pubkey_hash).hex()
                    
                    if utxo_script:
                        z, z_status = get_sighash_z_segwit(txid, idx, raw_tx, script_code_hex, utxo_value, sighash_type)
                        z_hex = format(z, '064x') if z else "UNKNOWN"
                    else:
                        z_hex = "UNKNOWN"
                    
                    sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                    sig_type_name = sig_type_names.get(sighash_type, f'0x{sighash_type:02x}')
                    
                    sig_data = (
                        f"txid: {txid}\n"
                        f"address: {address}\n"
                        f"pubkey: {pubkey.hex()}\n"
                        f"r: {format(r, '064x')}\n"
                        f"s: {format(s, '064x')}\n"
                        f"z: {z_hex}\n"
                        f"sighash: {sig_type_name}\n"
                        f"----------------------------------"
                    )
                    zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                    print(sig_data)
                    
                except Exception as e:
                    print(f"⚠️ Błąd P2WPKH {idx}: {e}")
            
            # P2WSH multisig
            elif len(witness) > 2 and utxo_type == 'P2WSH':
                try:
                    signatures_hex = find_all_der_signatures(witness_hex)
                    if not signatures_hex:
                        continue
                    
                    witness_script_hex = witness_hex[-1]
                    decoded_script = decode_script(witness_script_hex)
                    
                    if not decoded_script or len(decoded_script) < 3:
                        continue
                    
                    first_op = decoded_script[0]
                    last_op = decoded_script[-1]
                    
                    if first_op not in OP_N_MAPPING or last_op != OP_CHECKMULTISIG:
                        continue
                    
                    m_val = OP_N_MAPPING.get(first_op, 0)
                    n_val = OP_N_MAPPING.get(decoded_script[-2], 0) if len(decoded_script) >= 2 else 0
                    
                    if m_val <= 0 or n_val <= 0 or m_val > n_val:
                        continue
                    
                    pubkeys = extract_pubkeys_from_script(decoded_script)
                    if not pubkeys:
                        continue
                    
                    address = witness_script_to_address_p2wsh(witness_script_hex)
                    
                    for sig_hex in signatures_hex:
                        sig_bytes = bytes.fromhex(sig_hex)
                        sighash_type = 0x01
                        if sig_bytes and sig_bytes[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                            sighash_type = sig_bytes[-1]
                            der_sig = sig_bytes[:-1]
                        else:
                            der_sig = sig_bytes
                        
                        r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                        
                        if utxo_script:
                            z, z_status = get_sighash_z_segwit(txid, idx, raw_tx, witness_script_hex, utxo_value, sighash_type)
                            z_hex = format(z, '064x') if z else "UNKNOWN"
                        else:
                            z_hex = "UNKNOWN"
                        
                        sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                        sig_type_name = sig_type_names.get(sighash_type, f'0x{sighash_type:02x}')
                        
                        sig_data = (
                            f"txid: {txid}\n"
                            f"address: {address}\n"
                            f"pubkey: MULTISIG_{m_val}_of_{n_val}\n"
                            f"r: {format(r, '064x')}\n"
                            f"s: {format(s, '064x')}\n"
                            f"z: {z_hex}\n"
                            f"sighash: {sig_type_name}\n"
                            f"----------------------------------"
                        )
                        zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                        print(sig_data)
                                        
                except Exception as e:
                    print(f"⚠️ Błąd P2WSH multisig {idx}: {e}")
            
            # P2SH-P2WPKH (poprawione wykrywanie)
            elif len(witness) == 2 and utxo_type == 'P2SH':
                try:
                    script_sig_bytes = tx['inputs'][idx]['script_sig']
                    parts = parse_pushdata(script_sig_bytes)
                    
                    if len(parts) >= 1:
                        redeem_script_hex = parts[0].hex() if isinstance(parts[0], bytes) else parts[0]
                        if isinstance(redeem_script_hex, str) and len(redeem_script_hex) >= 44 and redeem_script_hex.startswith('0014'):
                            print(f"✅ Wykryto P2SH-P2WPKH")
                            sig_hex = witness_hex[0]
                            pubkey_hex = witness_hex[1]
                            
                            if not pubkey_hex or not is_compressed_pubkey(pubkey_hex):
                                continue
                            
                            sig_bytes = bytes.fromhex(sig_hex)
                            sighash_type = 0x01
                            if sig_bytes and sig_bytes[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                                sighash_type = sig_bytes[-1]
                                der_sig = sig_bytes[:-1]
                            else:
                                der_sig = sig_bytes
                            
                            r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                            pubkey = bytes.fromhex(pubkey_hex)
                            pubkey_hash = hash160(pubkey)
                            
                            address = pubkey_to_address_p2sh_p2wpkh(pubkey)
                            script_code_hex = get_p2wpkh_scriptcode(pubkey_hash).hex()
                            
                            if utxo_script:
                                z, z_status = get_sighash_z_segwit(txid, idx, raw_tx, script_code_hex, utxo_value, sighash_type)
                                z_hex = format(z, '064x') if z else "UNKNOWN"
                            else:
                                z_hex = "UNKNOWN"
                            
                            sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                            sig_type_name = sig_type_names.get(sighash_type, f'0x{sighash_type:02x}')
                            
                            sig_data = (
                                f"txid: {txid}\n"
                                f"address: {address}\n"
                                f"pubkey: {pubkey.hex()}\n"
                                f"r: {format(r, '064x')}\n"
                                f"s: {format(s, '064x')}\n"
                                f"z: {z_hex}\n"
                                f"sighash: {sig_type_name}\n"
                                f"----------------------------------"
                            )
                            zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                            print(sig_data)
                    
                except Exception as e:
                    print(f"⚠️ Błąd P2SH-P2WPKH {idx}: {e}")

            # ============================================================
            # DODANE: P2TR (Taproot)
            # ============================================================
            elif len(witness) == 2 and utxo_type == 'P2TR':
                try:
                    sig_hex = witness_hex[0]
                    pubkey_hex = witness_hex[1]
                    
                    if not pubkey_hex or not is_compressed_pubkey(pubkey_hex):
                        continue
                    
                    sig_bytes = bytes.fromhex(sig_hex)
                    sighash_type = 0x01
                    if sig_bytes and sig_bytes[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                        sighash_type = sig_bytes[-1]
                        der_sig = sig_bytes[:-1]
                    else:
                        der_sig = sig_bytes
                    
                    r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                    pubkey = bytes.fromhex(pubkey_hex)
                    pubkey_hash = hash160(pubkey)
                    
                    address = pubkey_to_address_p2wpkh(pubkey)
                    script_code_hex = get_p2wpkh_scriptcode(pubkey_hash).hex()
                    
                    if utxo_script:
                        z, z_status = get_sighash_z_segwit(txid, idx, raw_tx, script_code_hex, utxo_value, sighash_type)
                        z_hex = format(z, '064x') if z else "UNKNOWN"
                    else:
                        z_hex = "UNKNOWN"
                    
                    sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                    sig_type_name = sig_type_names.get(sighash_type, f'0x{sighash_type:02x}')
                    
                    sig_data = (
                        f"txid: {txid}\n"
                        f"address: {address}\n"
                        f"pubkey: {pubkey.hex()}\n"
                        f"r: {format(r, '064x')}\n"
                        f"s: {format(s, '064x')}\n"
                        f"z: {z_hex}\n"
                        f"sighash: {sig_type_name}\n"
                        f"----------------------------------"
                    )
                    zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                    print(sig_data)
                    
                except Exception as e:
                    print(f"⚠️ Błąd P2TR {idx}: {e}")

    # ============================================================
    # 2. OBSŁUGA P2SH MULTISIG (adresy 3)
    # ============================================================
    for idx, input_data in enumerate(tx['inputs']):
        script = input_data['script_sig'].hex()
        if not script:
            continue
        try:
            script_bytes = bytes.fromhex(script)
            parts = parse_pushdata(script_bytes)

            if len(parts) >= 3:
                last_item = parts[-1]
                if isinstance(last_item, bytes):
                    last_item = last_item.hex()
                
                if isinstance(last_item, str) and len(last_item) > 0:
                    redeem_script_hex = last_item
                    decoded_redeem = decode_script(redeem_script_hex)
                    
                    if decoded_redeem and len(decoded_redeem) >= 3:
                        first_op = decoded_redeem[0]
                        last_op = decoded_redeem[-1]
                        
                        if first_op in OP_N_MAPPING and last_op == OP_CHECKMULTISIG:
                            m_val = OP_N_MAPPING.get(first_op, 0)
                            n_val = OP_N_MAPPING.get(decoded_redeem[-2], 0) if len(decoded_redeem) >= 2 else 0
                            
                            if m_val > 0 and n_val > 0 and m_val <= n_val:
                                signatures_hex = []
                                for part in parts[:-1]:
                                    if isinstance(part, bytes):
                                        part_hex = part.hex()
                                    else:
                                        part_hex = part
                                    if is_der_signature(part_hex):
                                        signatures_hex.append(part_hex)
                                
                                if not signatures_hex:
                                    continue
                                
                                pubkeys = extract_pubkeys_from_script(decoded_redeem)
                                if not pubkeys:
                                    continue
                                
                                address = redeem_script_to_address_p2sh(redeem_script_hex)
                                
                                for sig_hex in signatures_hex:
                                    if len(sig_hex) >= 2 and sig_hex.endswith(('01','02','03','81','82','83')):
                                        sig_to_parse = sig_hex[:-2]
                                        sighash_byte = int(sig_hex[-2:], 16)
                                    else:
                                        sig_to_parse = sig_hex
                                        sighash_byte = 0x01
                                    
                                    try:
                                        r, s = util.sigdecode_der(bytes.fromhex(sig_to_parse), SECP256k1.order)
                                    except:
                                        continue
                                    
                                    z, z_status = get_sighash_z_legacy(txid, idx, raw_tx, redeem_script_hex, 0, sighash_byte)
                                    z_hex = format(z, '064x') if z else "UNKNOWN"
                                    
                                    sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                                    sig_type_name = sig_type_names.get(sighash_byte, f'0x{sighash_byte:02x}')
                                    
                                    sig_data = (
                                        f"txid: {txid}\n"
                                        f"address: {address}\n"
                                        f"pubkey: MULTISIG_{m_val}_of_{n_val}\n"
                                        f"r: {format(r, '064x')}\n"
                                        f"s: {format(s, '064x')}\n"
                                        f"z: {z_hex}\n"
                                        f"sighash: {sig_type_name}\n"
                                        f"----------------------------------"
                                    )
                                    zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                                    print(sig_data)

        except Exception as e:
            print(f"⚠️ Błąd P2SH multisig: {e}")

    # ============================================================
    # 3. TWOJA ORYGINALNA METODA DLA ADRESÓW 1 - BEZ ZMIAN!
    # ============================================================
    for idx, input_data in enumerate(tx['inputs']):
        script = input_data['script_sig'].hex()
        if not script:
            continue
        try:
            script_bytes = bytes.fromhex(script)
            parts = parse_pushdata(script_bytes)

            for i in range(len(parts) - 1):
                sig_candidate = parts[i]
                pub_candidate = parts[i + 1]

                if len(sig_candidate) > 8 and sig_candidate[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83) and pub_candidate[0] in (0x02, 0x03, 0x04):
                    try:
                        sighash_byte = sig_candidate[-1]
                        der_sig = sig_candidate[:-1]
                        r, s = util.sigdecode_der(der_sig, SECP256k1.order)
                        pubkey = pub_candidate
                        pubkey_hash = hash160(pubkey)
                        
                        script_code_hex = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
                        
                        z, z_status = get_sighash_z_legacy(txid, idx, raw_tx, script_code_hex.hex(), 0, sighash_byte)
                        z_hex = format(z, '064x') if z else "UNKNOWN"
                        
                        address = pubkey_to_address(pubkey)

                        if not address.startswith("1"):
                            continue

                        sig_type_names = {0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE', 0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY'}
                        sig_type_name = sig_type_names.get(sighash_byte, f'0x{sighash_byte:02x}')

                        sig_data = (
                            f"txid: {txid}\naddress: {address}\npubkey: {pubkey.hex()}\n"
                            f"r: {format(r, '064x')}\ns: {format(s, '064x')}\nz: {z_hex}\nsighash: {sig_type_name}\n----------------------------------"
                        )
                        zapisz_do_pliku(SIGNATURES_FILE, sig_data)
                        print(sig_data)
                    except Exception as inner:
                        print(f"⚠️ Nie udało się przetworzyć podpisu {i}: {inner}")

        except Exception as e:
            print(f"⚠️ Błąd przy wejściu {idx}: {e}")

def odczytaj_ostatni_txid():
    if not os.path.exists(LAST_TXID_FILE):
        return None
    with open(LAST_TXID_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def zapisz_ostatni_txid(txid):
    with open(LAST_TXID_FILE, "w", encoding="utf-8") as f:
        f.write(txid)

def process_txids_from_file(file):
    print(f"📂 Wczytuję z pliku: {file}")
    if not os.path.exists(file):
        print(f"❌ Brak pliku {file}.")
        return

    last_txid = odczytaj_ostatni_txid()
    found_last = last_txid is None

    with open(file, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            txid = line.strip()
            if len(txid) != 64:
                print(f"⚠️ [{line_number}] Nieprawidłowy TXID: {txid}")
                continue

            if not found_last:
                if txid == last_txid:
                    print("✅ Znaleziono ostatni TXID – kontynuuję...")
                    found_last = True
                continue

            print(f"\n🚀 [{line_number}] PRZETWARZAM TXID: {txid}")
            process_transaction(txid)
            zapisz_ostatni_txid(txid)
            print(f"🕒 Czekam {DELAY_BETWEEN_TX}s przed kolejnym...")
            time.sleep(DELAY_BETWEEN_TX)

    print("\n✅ Wszystkie TXID przetworzone.")

if __name__ == "__main__":
    print("🚀 STARTUJĘ!")
    print("📌 Obsługiwane adresy:")
    print("   - 1 (P2PKH Legacy) - obsługa wszystkich SIGHASH")
    print("   - 3 (P2SH-P2WPKH, P2SH multisig)")
    print("   - bc1 (P2WPKH, P2WSH multisig, P2TR Taproot)")
    print("📌 Poprawne z dla wszystkich typów (BIP143 dla SegWit, bez odwracania TXID w preimage)")
    print(f"📌 User-Agentów: {len(USER_AGENTS)} różnych")
    print(f"📌 Limit błędów API: {MAX_API_FAILURES}")
    process_txids_from_file(TXID_FILE)
    print("\n✅ Zakończono.")