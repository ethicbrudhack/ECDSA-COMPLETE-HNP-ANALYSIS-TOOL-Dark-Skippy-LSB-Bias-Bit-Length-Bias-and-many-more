#!/usr/bin/env python3
"""
GŁĘBOKA ANALIZA KONKRETNEGO ADRESU BITCOIN
Skrypt analizuje wszystkie transakcje dla podanego adresu/pubkey
"""

import sys
import json
from collections import defaultdict, Counter
from math import sqrt, log2
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
import hashlib
import base58

# ============================================================
# PARAMETRY KRZYWEJ secp256k1
# ============================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# ============================================================
# STRUKTURA PODPISU
# ============================================================
@dataclass
class Signature:
    txid: str
    address: str
    pubkey: str
    r: int
    s: int
    z: int
    sighash: str = "ALL"
    is_multisig: bool = False
    
    def __post_init__(self):
        if not (1 <= self.r < N and 1 <= self.s < N):
            raise ValueError(f"Nieprawidłowe r lub s dla transakcji {self.txid}")

# ============================================================
# FUNKCJE POMOCNICZE
# ============================================================
def modinv(a: int, m: int = N) -> int:
    return pow(a, m-2, m)

def parse_tx_file(filename: str) -> List[Signature]:
    signatures = []
    current = {}
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('---') or line.startswith('==='):
                if current and 'txid' in current:
                    try:
                        sig = Signature(
                            txid=current['txid'],
                            address=current.get('address', 'UNKNOWN'),
                            pubkey=current.get('pubkey', 'UNKNOWN'),
                            r=current['r'],
                            s=current['s'],
                            z=current.get('z', 0),
                            sighash=current.get('sighash', 'ALL'),
                            is_multisig='multisig' in current
                        )
                        signatures.append(sig)
                    except (ValueError, KeyError) as e:
                        print(f"⚠️ Pomijam niepełną transakcję: {e}")
                current = {}
                continue
                
            if line.startswith('txid:'):
                current['txid'] = line.replace('txid:', '').strip()
            elif line.startswith('address:'):
                current['address'] = line.replace('address:', '').strip()
            elif line.startswith('pubkey:'):
                current['pubkey'] = line.replace('pubkey:', '').strip()
            elif line.startswith('r:'):
                current['r'] = int(line.replace('r:', '').strip(), 16)
            elif line.startswith('s:'):
                current['s'] = int(line.replace('s:', '').strip(), 16)
            elif line.startswith('z:'):
                try:
                    current['z'] = int(line.replace('z:', '').strip(), 16)
                except ValueError:
                    current['z'] = 0
            elif line.startswith('sighash:'):
                current['sighash'] = line.replace('sighash:', '').strip()
            elif 'multisig' in line:
                current['multisig'] = True
    
    if current and 'txid' in current:
        try:
            sig = Signature(
                txid=current['txid'],
                address=current.get('address', 'UNKNOWN'),
                pubkey=current.get('pubkey', 'UNKNOWN'),
                r=current['r'],
                s=current['s'],
                z=current.get('z', 0),
                sighash=current.get('sighash', 'ALL'),
                is_multisig='multisig' in current
            )
            signatures.append(sig)
        except (ValueError, KeyError):
            pass
    
    return signatures

def pubkey_to_address(pubkey_hex: str) -> str:
    """Konwertuje pubkey na adres Bitcoin"""
    try:
        # SHA-256
        sha = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
        # RIPEMD-160
        ripemd = hashlib.new('ripemd160')
        ripemd.update(sha)
        # Version byte (0x00 for mainnet)
        network = b'\x00' + ripemd.digest()
        # Checksum
        checksum = hashlib.sha256(hashlib.sha256(network).digest()).digest()[:4]
        # Base58 encode
        address = base58.b58encode(network + checksum).decode()
        return address
    except:
        return "ERROR"

def shannon_entropy(counter: Counter, total: int) -> float:
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * log2(p)
    return entropy

# ============================================================
# TESTY ANALITYCZNE
# ============================================================

def detect_reused_nonce(signatures: List[Signature]) -> Dict:
    r_map = defaultdict(list)
    for idx, sig in enumerate(signatures):
        r_map[sig.r].append((idx, sig))
    
    reused = {}
    for r, sigs in r_map.items():
        if len(sigs) > 1:
            reused[hex(r)] = {
                'count': len(sigs),
                'transactions': [s[1].txid for s in sigs],
                'indices': [s[0] for s in sigs]
            }
    
    if reused:
        return {
            'found': True,
            'details': reused,
            'note': 'REUSED NONCE - ALGEBRAICZNE ODZYSKANIE KLUCZA!'
        }
    return {'found': False}

def analyze_r_distances(signatures: List[Signature]) -> Dict:
    if len(signatures) < 3:
        return {'error': 'Za mało podpisów', 'note': 'Potrzeba >=3'}
    
    r_values = [sig.r for sig in signatures]
    distances = [abs(r_values[i+1] - r_values[i]) for i in range(len(r_values)-1)]
    
    if not distances:
        return {'error': 'Brak danych'}
    
    avg_dist = sum(distances) / len(distances)
    min_dist = min(distances)
    max_dist = max(distances)
    
    small_distances = [d for d in distances if d < 2**16]
    small_count = len(small_distances)
    small_ratio = small_count / len(distances) if distances else 0
    
    is_suspicious = small_count > 0
    
    return {
        'sample_size': len(signatures),
        'total_pairs': len(distances),
        'avg_distance': avg_dist,
        'min_distance': min_dist,
        'max_distance': max_dist,
        'small_distances_count': small_count,
        'small_distances_ratio': small_ratio,
        'small_distances': small_distances[:10],
        'is_suspicious': is_suspicious,
        'note': f'Znaleziono {small_count} bardzo małych odległości (<2^16)' if is_suspicious else 'Brak małych odległości'
    }

def analyze_bit_bias(signatures: List[Signature]) -> Dict:
    sample_size = len(signatures)
    
    if sample_size < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {sample_size}'}
    
    bit_counts = [0] * 256
    for sig in signatures:
        r = sig.r
        for i in range(256):
            if (r >> i) & 1:
                bit_counts[i] += 1
    
    suspicious_bits = []
    sigma = sqrt(0.25 / sample_size)
    
    for bit, count in enumerate(bit_counts):
        ratio = count / sample_size
        deviation = abs(ratio - 0.5) / sigma if sigma > 0 else 0
        
        if deviation > 4.5:
            suspicious_bits.append({
                'bit': bit,
                'ratio': ratio,
                'deviation_sigma': deviation,
                'type': 'MSB' if bit >= 248 else 'LSB' if bit < 8 else 'middle'
            })
    
    is_suspicious = len(suspicious_bits) > 0
    
    return {
        'sample_size': sample_size,
        'suspicious_bits': suspicious_bits,
        'count': len(suspicious_bits),
        'is_suspicious': is_suspicious,
        'note': f'Znaleziono {len(suspicious_bits)} bitów odbiegających od normy (>4.5σ)' if is_suspicious else 'Brak podejrzanych bitów'
    }

def runs_test_sequence(signatures: List[Signature]) -> Dict:
    sample_size = len(signatures)
    
    if sample_size < 50:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=50, masz {sample_size}'}
    
    bits = [sig.r & 1 for sig in signatures]
    
    runs = 0
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    
    ones = sum(bits)
    zeros = len(bits) - ones
    
    expected_runs = (2 * ones * zeros) / len(bits) + 1 if len(bits) > 0 else 0
    
    var_runs = (2 * ones * zeros * (2 * ones * zeros - len(bits))) / (len(bits) * len(bits) * (len(bits) - 1))
    sigma = sqrt(var_runs) if var_runs > 0 else 0
    
    deviation_sigma = abs(runs - expected_runs) / sigma if sigma > 0 else 0
    is_suspicious = deviation_sigma > 4.0
    
    return {
        'sample_size': sample_size,
        'runs': runs,
        'expected_runs': expected_runs,
        'deviation_sigma': deviation_sigma,
        'ones': ones,
        'zeros': zeros,
        'is_suspicious': is_suspicious,
        'note': 'Podejrzany runs test' if is_suspicious else 'Normalny runs test'
    }

def mutual_information(signatures: List[Signature]) -> Dict:
    sample_size = len(signatures)
    
    if sample_size < 50:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=50, masz {sample_size}'}
    
    bits = [sig.r & 1 for sig in signatures]
    
    joint_counts = Counter()
    for i in range(len(bits) - 1):
        pair = (bits[i], bits[i+1])
        joint_counts[pair] += 1
    
    total = len(bits) - 1
    
    p0 = sum(1 for b in bits if b == 0) / len(bits)
    p1 = 1 - p0
    
    mi = 0.0
    for (b1, b2), count in joint_counts.items():
        p_joint = count / total
        p1_b = p0 if b1 == 0 else p1
        p2_b = p0 if b2 == 0 else p1
        if p_joint > 0 and p1_b > 0 and p2_b > 0:
            mi += p_joint * log2(p_joint / (p1_b * p2_b))
    
    is_suspicious = mi > 0.01
    
    return {
        'sample_size': sample_size,
        'mutual_information': mi,
        'is_suspicious': is_suspicious,
        'note': f'Mutual Information = {mi:.4f}' + (' - podejrzane!' if is_suspicious else ' - normalne')
    }

def analyze_hnp_structure(signatures: List[Signature]) -> Dict:
    sample_size = len(signatures)
    
    if sample_size < 10:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=10, masz {sample_size}'}
    
    has_z = all(sig.z > 0 for sig in signatures)
    if not has_z:
        return {'error': 'Brak z (hasha) dla niektórych podpisów', 'note': 'Potrzebne do HNP'}
    
    t_values = []
    u_values = []
    tu_pairs = []
    
    for sig in signatures:
        try:
            s_inv = modinv(sig.s, N)
            t = (sig.r * s_inv) % N
            u = (sig.z * s_inv) % N
            t_values.append(t)
            u_values.append(u)
            tu_pairs.append((t, u))
        except:
            continue
    
    if not t_values:
        return {'error': 'Nie można obliczyć t_i i u_i'}
    
    n = len(t_values)
    
    unique_t = len(set(t_values))
    unique_u = len(set(u_values))
    unique_tu = len(set(tu_pairs))
    
    tu_counter = Counter(tu_pairs)
    repeated_pairs = [(hex(t), hex(u), count) for (t, u), count in tu_counter.items() if count > 1]
    
    t_counter = Counter(t_values)
    repeated_t = [(hex(t), count) for t, count in t_counter.items() if count > 1]
    
    is_suspicious = len(repeated_pairs) > 0 or len(repeated_t) > 0
    
    return {
        'sample_size': n,
        'unique_t': unique_t,
        'unique_u': unique_u,
        'unique_tu': unique_tu,
        'repeated_pairs_count': len(repeated_pairs),
        'repeated_pairs': repeated_pairs[:5],
        'repeated_t_count': len(repeated_t),
        'repeated_t': repeated_t[:5],
        'is_suspicious': is_suspicious,
        'note': f'Znaleziono {len(repeated_pairs)} powtarzających się par (t,u)' if is_suspicious else 'Brak powtarzających się par'
    }

def calculate_risk_score(signatures: List[Signature]) -> Dict:
    sample_size = len(signatures)
    
    reused = detect_reused_nonce(signatures)
    if reused['found']:
        return {
            'risk_score': 100,
            'confidence': 1.0,
            'level': 'CRITICAL',
            'reasons': ['REUSED_NONCE'],
            'reused_nonce': reused,
            'note': 'NATYCHMIASTOWE ODZYSKANIE KLUCZA - reused nonce!'
        }
    
    if sample_size < 50:
        return {
            'risk_score': 0,
            'confidence': 0.0,
            'level': 'INSUFFICIENT_DATA',
            'note': f'Za mało podpisów ({sample_size}) - potrzeba >=50'
        }
    
    risk_score = 0
    reasons = []
    
    # Różne testy
    tests = [
        ('r_distances', analyze_r_distances(signatures)),
        ('bit_bias', analyze_bit_bias(signatures)),
        ('runs', runs_test_sequence(signatures)),
        ('mutual_info', mutual_information(signatures)),
        ('hnp', analyze_hnp_structure(signatures))
    ]
    
    for name, result in tests:
        if 'error' not in result and result.get('is_suspicious', False):
            if name == 'r_distances':
                risk_score += 15
                reasons.append("SMALL_R_DISTANCES")
            elif name == 'bit_bias':
                risk_score += 20
                reasons.append("BIT_BIAS")
            elif name == 'runs':
                risk_score += 15
                reasons.append("RUNS")
            elif name == 'mutual_info':
                risk_score += 20
                reasons.append("MUTUAL_INFO")
            elif name == 'hnp':
                risk_score += 20
                reasons.append("HNP_STRUCTURE")
    
    confidence = min(1.0, sample_size / 500)
    
    if risk_score >= 35:
        level = 'HIGH'
        note = 'Podejrzenie biasu w r - zalecana dalsza analiza'
    elif risk_score >= 15:
        level = 'MEDIUM'
        note = 'Podejrzane wzorce w r'
    else:
        level = 'LOW'
        note = 'Brak podejrzanych wzorców w r'
    
    return {
        'risk_score': risk_score,
        'confidence': confidence,
        'level': level,
        'reasons': reasons,
        'note': note,
        'sample_size': sample_size,
        'limitation': 'Analiza oparta na r, nie na k. Subtelne wycieki bitów k mogą być niewidoczne.'
    }

# ============================================================
# GŁÓWNA FUNKCJA ANALIZY
# ============================================================

def analyze_address_deep(address: str, pubkey: str, signatures: List[Signature]) -> Dict:
    """Głęboka analiza konkretnego adresu"""
    
    # Filtruj podpisy dla tego adresu
    sigs = [s for s in signatures if s.address == address or s.pubkey == pubkey]
    
    # Sprawdź czy znaleziono
    if not sigs:
        return {'error': 'Nie znaleziono podpisów dla tego adresu/pubkey'}
    
    # ============================================================
    # RAPORT
    # ============================================================
    print("\n" + "="*100)
    print(f"🔍 GŁĘBOKA ANALIZA ADRESU")
    print("="*100)
    print(f"Adres:  {address}")
    print(f"Pubkey: {pubkey}")
    print(f"Liczba podpisów: {len(sigs)}")
    print("="*100)
    
    results = {
        'address': address,
        'pubkey': pubkey,
        'signature_count': len(sigs),
        'transactions': []
    }
    
    # ============================================================
    # 1. LISTA WSZYSTKICH TRANSAKCJI
    # ============================================================
    print("\n" + "─"*100)
    print("📋 LISTA TRANSAKCJI")
    print("─"*100)
    
    for i, sig in enumerate(sigs, 1):
        print(f"\n[{i}] TXID: {sig.txid}")
        print(f"    r: {hex(sig.r)}")
        print(f"    s: {hex(sig.s)}")
        print(f"    z: {hex(sig.z)}")
        print(f"    Sighash: {sig.sighash}")
        
        results['transactions'].append({
            'txid': sig.txid,
            'r': hex(sig.r),
            's': hex(sig.s),
            'z': hex(sig.z),
            'sighash': sig.sighash
        })
    
    # ============================================================
    # 2. REUSED NONCE
    # ============================================================
    print("\n" + "─"*100)
    print("🔍 REUSED NONCE CHECK")
    print("─"*100)
    
    reused = detect_reused_nonce(sigs)
    results['reused_nonce'] = reused
    
    if reused['found']:
        print("⚠️⚠️⚠️ ZNALEZIONO REUSED NONCE!")
        for r, details in reused['details'].items():
            print(f"  r={r[:20]}... występuje {details['count']} razy")
            print(f"  Transakcje: {', '.join(details['transactions'])}")
        print("\n  🎯 MOŻLIWE ALGEBRAICZNE ODZYSKANIE KLUCZA!")
    else:
        print("  ✅ Brak reused nonce")
    
    # ============================================================
    # 3. STATYSTYKI PODSTAWOWE
    # ============================================================
    print("\n" + "─"*100)
    print("📊 STATYSTYKI PODSTAWOWE")
    print("─"*100)
    
    # r values
    r_values = [sig.r for sig in sigs]
    print(f"\n  r:")
    print(f"    Min: {hex(min(r_values))}")
    print(f"    Max: {hex(max(r_values))}")
    print(f"    Średnia: {sum(r_values) / len(r_values):.2f}")
    
    # Sprawdź małe r
    small_r = [s for s in sigs if s.r < 2**80]
    if small_r:
        print(f"    ⚠️ Małe r (<2^80): {len(small_r)} podpisów")
        for sig in small_r:
            print(f"       - {sig.txid[:20]}... r={hex(sig.r)[:20]}...")
    
    # z values
    z_values = [sig.z for sig in sigs if sig.z > 0]
    print(f"\n  z (hash):")
    print(f"    Podpisy z z: {len(z_values)}/{len(sigs)}")
    if z_values:
        print(f"    Min z: {hex(min(z_values))}")
        print(f"    Max z: {hex(max(z_values))}")
    
    # ============================================================
    # 4. TESTY ANALITYCZNE (jeśli >=20 podpisów)
    # ============================================================
    if len(sigs) >= 20:
        print("\n" + "─"*100)
        print("🧪 TESTY ANALITYCZNE")
        print("─"*100)
        
        # Odległości między r
        print("\n  📏 Odległości między r:")
        dist = analyze_r_distances(sigs)
        if 'error' not in dist:
            print(f"    Średnia odległość: {dist['avg_distance']:.2f}")
            print(f"    Minimalna odległość: {dist['min_distance']}")
            print(f"    Maksymalna odległość: {dist['max_distance']}")
            print(f"    Małe odległości (<2^16): {dist['small_distances_count']}")
            if dist.get('is_suspicious'):
                print("    ⚠️ ZNALEZIONO MAŁE ODLEGŁOŚCI!")
        
        # Bias bitów
        print("\n  🎯 Bias bitów:")
        bias = analyze_bit_bias(sigs)
        if 'error' not in bias:
            print(f"    Podejrzane bity: {bias['count']}")
            if bias.get('is_suspicious'):
                print("    ⚠️ ZNALEZIONO BIAS!")
                for b in bias['suspicious_bits'][:5]:
                    print(f"      Bit {b['bit']:3d} ({b['type']}): {b['ratio']:.2%} ({b['deviation_sigma']:.2f}σ)")
        
        # Runs test (jeśli >=50)
        if len(sigs) >= 50:
            print("\n  🎲 Runs test:")
            runs = runs_test_sequence(sigs)
            if 'error' not in runs:
                print(f"    Liczba runów: {runs['runs']} (oczekiwane: {runs['expected_runs']:.1f})")
                print(f"    Odchylenie: {runs['deviation_sigma']:.2f}σ")
                if runs.get('is_suspicious'):
                    print("    ⚠️ PODEJRZANY!")
        
        # Mutual Information (jeśli >=50)
        if len(sigs) >= 50:
            print("\n  🔄 Mutual Information:")
            mi = mutual_information(sigs)
            if 'error' not in mi:
                print(f"    MI: {mi['mutual_information']:.4f}")
                if mi.get('is_suspicious'):
                    print("    ⚠️ PODEJRZANY!")
        
        # HNP Structure
        print("\n  🧩 Struktura HNP:")
        hnp = analyze_hnp_structure(sigs)
        if 'error' not in hnp:
            print(f"    Unikalne (t,u): {hnp['unique_tu']}/{hnp['sample_size']}")
            print(f"    Powtarzające się pary: {hnp['repeated_pairs_count']}")
            if hnp.get('is_suspicious'):
                print("    ⚠️ ZNALEZIONO POWTARZAJĄCE SIĘ PARY!")
                for t, u, count in hnp['repeated_pairs'][:3]:
                    print(f"      t={t[:20]}..., u={u[:20]}... ({count}x)")
        
        # ============================================================
        # 5. RISK SCORE
        # ============================================================
        print("\n" + "─"*100)
        print("📊 RISK SCORE")
        print("─"*100)
        
        risk = calculate_risk_score(sigs)
        results['risk'] = risk
        
        print(f"\n  Risk Score: {risk['risk_score']}/100")
        print(f"  Confidence: {risk['confidence']:.2f}")
        print(f"  Level: {risk['level']}")
        print(f"  {risk['note']}")
        
        if risk['reasons']:
            print(f"\n  Czynniki ryzyka:")
            for reason in risk['reasons']:
                print(f"    - {reason}")
        
        if 'limitation' in risk:
            print(f"\n  ⚠️ {risk['limitation']}")
    
    # ============================================================
    # 6. ADRES Z PUBKEY
    # ============================================================
    print("\n" + "─"*100)
    print("🔑 WERYFIKACJA ADRESU")
    print("─"*100)
    
    calculated_address = pubkey_to_address(pubkey)
    print(f"  Adres z pubkey: {calculated_address}")
    print(f"  Podany adres:   {address}")
    if calculated_address == address:
        print("  ✅ Adresy się zgadzają")
    else:
        print("  ⚠️ Adresy NIE zgadzają się - sprawdź pubkey")
    
    # ============================================================
    # 7. PODSUMOWANIE
    # ============================================================
    print("\n" + "="*100)
    print("📋 PODSUMOWANIE")
    print("="*100)
    
    print(f"\n  Adres: {address}")
    print(f"  Liczba transakcji: {len(sigs)}")
    
    if reused['found']:
        print("  ⚠️⚠️⚠️ CRITICAL: REUSED NONCE - MOŻNA ODZYSKAĆ KLUCZ!")
    elif len(sigs) >= 50:
        level = risk.get('level', 'UNKNOWN')
        if level == 'HIGH':
            print("  ⚠️ HIGH RISK: Podejrzenie biasu w r")
        elif level == 'MEDIUM':
            print("  ⚠️ MEDIUM RISK: Podejrzane wzorce w r")
        else:
            print("  ✅ LOW RISK: Brak podejrzanych wzorców")
    else:
        print(f"  ⚠️ Za mało podpisów ({len(sigs)}) do pełnej analizy")
        print(f"  Potrzeba >=50 podpisów dla testów statystycznych")
    
    print("\n" + "="*100)
    
    return results

# ============================================================
# ZAPIS RAPORTU
# ============================================================

def save_report(results: Dict, filename: str = None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"deep_analysis_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*100 + "\n")
        f.write("RAPORT GŁĘBOKIEJ ANALIZY ADRESU\n")
        f.write("="*100 + "\n\n")
        f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Adres: {results.get('address', 'N/A')}\n")
        f.write(f"Pubkey: {results.get('pubkey', 'N/A')}\n")
        f.write(f"Liczba podpisów: {results.get('signature_count', 0)}\n\n")
        
        # Transakcje
        f.write("-"*100 + "\n")
        f.write("TRANSAKCJE\n")
        f.write("-"*100 + "\n\n")
        for i, tx in enumerate(results.get('transactions', []), 1):
            f.write(f"[{i}] TXID: {tx['txid']}\n")
            f.write(f"    r: {tx['r']}\n")
            f.write(f"    s: {tx['s']}\n")
            f.write(f"    z: {tx['z']}\n")
            f.write(f"    Sighash: {tx.get('sighash', 'ALL')}\n\n")
        
        # Reused nonce
        reused = results.get('reused_nonce', {})
        if reused.get('found'):
            f.write("-"*100 + "\n")
            f.write("⚠️⚠️⚠️ REUSED NONCE\n")
            f.write("-"*100 + "\n\n")
            for r, details in reused['details'].items():
                f.write(f"r={r[:30]}... występuje {details['count']} razy\n")
                f.write(f"Transakcje: {', '.join(details['transactions'])}\n\n")
        
        # Risk
        risk = results.get('risk', {})
        if risk:
            f.write("-"*100 + "\n")
            f.write("RISK SCORE\n")
            f.write("-"*100 + "\n\n")
            f.write(f"Risk Score: {risk.get('risk_score', 0)}/100\n")
            f.write(f"Confidence: {risk.get('confidence', 0):.2f}\n")
            f.write(f"Level: {risk.get('level', 'UNKNOWN')}\n")
            f.write(f"Note: {risk.get('note', 'N/A')}\n")
            if risk.get('reasons'):
                f.write(f"Czynniki: {', '.join(risk['reasons'])}\n")
    
    print(f"\n💾 Zapisano raport do: {filename}")
    return filename

# ============================================================
# MAIN
# ============================================================

def main():
    # Konkretny adres i pubkey do analizy
    TARGET_ADDRESS = "19MeFRgE2CPYWaezV2XuXPcT8LBpxkj8JN"
    TARGET_PUBKEY = "02135605874100d749f079aee060392605d6b4008ad95ea52907ccf57c3e056ed2"
    
    if len(sys.argv) < 2:
        print("Użycie: python deep_analysis.py <plik_z_transakcjami.txt>")
        print(f"\nAnalizuje adres: {TARGET_ADDRESS}")
        print(f"Pubkey: {TARGET_PUBKEY}")
        sys.exit(1)
    
    filename = sys.argv[1]
    print(f"📂 Wczytywanie danych z: {filename}")
    
    signatures = parse_tx_file(filename)
    print(f"✅ Wczytano {len(signatures)} poprawnych podpisów")
    
    if not signatures:
        print("❌ Brak poprawnych podpisów")
        sys.exit(1)
    
    # Analiza
    results = analyze_address_deep(TARGET_ADDRESS, TARGET_PUBKEY, signatures)
    
    if 'error' in results:
        print(f"\n❌ {results['error']}")
        print(f"💡 Sprawdź czy plik zawiera ten adres/pubkey")
        sys.exit(1)
    
    # Zapisz raport
    save_report(results)
    
    print("\n✅ Analiza zakończona!")

if __name__ == "__main__":
    main()
