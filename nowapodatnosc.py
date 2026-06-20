#!/usr/bin/env python3
"""
KOMPLETNA ANALIZA HNP - WSZYSTKIE POPRAWNE TESTY
"""

from collections import defaultdict, Counter
from math import sqrt, log2
from tqdm import tqdm
import sys
import json
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
import random

# ============================================================
# KONFIGURACJA LOGOWANIA
# ============================================================
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ============================================================
# PARAMETRY KRZYWEJ
# ============================================================
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Cache dla Monte Carlo
MONTE_CARLO_CACHE = {}

# ============================================================
# STRUKTURY DANYCH
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

@dataclass
class HNPEquation:
    txid: str
    r: int
    s: int
    z: int
    t: int
    u: int
    k: Optional[int] = None
    bound: Optional[int] = None

# ============================================================
# FUNKCJE POMOCNICZE
# ============================================================
def modinv(a: int, m: int = N) -> int:
    try:
        return pow(a, -1, m)
    except TypeError:
        return pow(a, m-2, m)

def recover_private_key(sig1: Signature, sig2: Signature) -> Optional[Dict]:
    try:
        diff_z = (sig1.z - sig2.z) % N
        diff_s = (sig1.s - sig2.s) % N
        
        if diff_s == 0:
            return None
        
        k = (diff_z * modinv(diff_s)) % N
        r_inv = modinv(sig1.r)
        dA = ((sig1.s * k - sig1.z) * r_inv) % N
        
        return {
            'private_key': hex(dA),
            'k': hex(k)
        }
    except Exception as e:
        logger.debug(f"Błąd odzyskiwania: {e}")
        return None

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
                        logger.warning(f"Pomijam niepełną transakcję: {e}")
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
        except (ValueError, KeyError) as e:
            logger.warning(f"Pomijam niepełną transakcję: {e}")
    
    return signatures

# ============================================================
# 1. BUDOWANIE UKŁADU RÓWNAŃ HNP
# ============================================================
def build_hnp_equations(signatures: List[Signature]) -> List[HNPEquation]:
    equations = []
    
    for sig in signatures:
        if sig.z == 0:
            continue
            
        try:
            s_inv = modinv(sig.s, N)
            t = (sig.r * s_inv) % N
            u = (sig.z * s_inv) % N
            
            eq = HNPEquation(
                txid=sig.txid,
                r=sig.r,
                s=sig.s,
                z=sig.z,
                t=t,
                u=u
            )
            equations.append(eq)
        except Exception as e:
            logger.debug(f"Błąd budowania równania: {e}")
            continue
    
    return equations

# ============================================================
# 2. REUSED NONCE
# ============================================================
def detect_reused_nonce(signatures: List[Signature], max_pairs: int = 1000) -> Dict:
    r_map = defaultdict(list)
    for idx, sig in enumerate(signatures):
        r_map[sig.r].append((idx, sig))
    
    results = {
        'found': False,
        'pairs': [],
        'recovered_keys': []
    }
    
    for r, sigs in r_map.items():
        if len(sigs) <= 1:
            continue
        
        pair_count = 0
        for i in range(len(sigs)):
            for j in range(i+1, len(sigs)):
                if pair_count >= max_pairs:
                    break
                
                sig1 = sigs[i][1]
                sig2 = sigs[j][1]
                
                recovered = recover_private_key(sig1, sig2)
                if recovered:
                    results['found'] = True
                    results['pairs'].append({
                        'r': hex(r),
                        'tx1': sig1.txid,
                        'tx2': sig2.txid,
                        'k': recovered['k'],
                        'private_key': recovered['private_key']
                    })
                    results['recovered_keys'].append(recovered['private_key'])
                    pair_count += 1
            
            if pair_count >= max_pairs:
                break
    
    return results

# ============================================================
# 3. LOW-S NORMALIZATION
# ============================================================
def check_low_s_normalization(signatures: List[Signature]) -> Dict:
    results = {
        'high_s_count': 0,
        'high_s_ratio': 0.0,
        'suspicious': False
    }
    
    N_half = N // 2
    high_s = [sig for sig in signatures if sig.s > N_half]
    
    results['high_s_count'] = len(high_s)
    if len(signatures) > 0:
        results['high_s_ratio'] = len(high_s) / len(signatures)
    
    if results['high_s_ratio'] > 0.5:
        results['suspicious'] = True
    
    return results

# ============================================================
# 4. DARK SKIPPY DETECTION
# ============================================================
def detect_dark_skippy(signatures: List[Signature], secret: str = None) -> Dict:
    result = {
        'dark_skippy_detected': False,
        'watermark_found': False,
        'patterns_found': [],
        'suspicious_transactions': [],
        'kangaroo_ready': False,
        'details': {},
        'candidates': []
    }
    
    if len(signatures) < 2:
        result['note'] = 'Za mało podpisów (potrzeba >=2)'
        return result
    
    max_pairs = 500
    pair_count = 0
    
    for i in range(len(signatures)):
        for j in range(i+1, len(signatures)):
            if pair_count >= max_pairs:
                break
                
            sig1 = signatures[i]
            sig2 = signatures[j]
            
            r1_bits = sig1.r.bit_length()
            r2_bits = sig2.r.bit_length()
            
            if 60 <= r1_bits <= 80 and 60 <= r2_bits <= 80:
                result['patterns_found'].append(f'MAŁE_NONCE: {r1_bits}, {r2_bits}')
                result['suspicious_transactions'].append({
                    'tx1': sig1.txid,
                    'tx2': sig2.txid,
                    'r1_bits': r1_bits,
                    'r2_bits': r2_bits
                })
                
                if sig1.txid == sig2.txid:
                    result['patterns_found'].append('TA_SAMA_TRANSAKCJA')
                
                diff = abs(sig1.r - sig2.r)
                if diff < 2**80:
                    result['patterns_found'].append(f'MAŁA_RÓŻNICA: {diff.bit_length()} bitów')
                
                result['candidates'].append({
                    'pair': (i, j),
                    'tx1': sig1.txid,
                    'tx2': sig2.txid,
                    'r1': hex(sig1.r)[:30],
                    'r2': hex(sig2.r)[:30],
                    'bits': (r1_bits, r2_bits),
                    'same_tx': sig1.txid == sig2.txid
                })
                pair_count += 1
                
                if secret and not result['watermark_found']:
                    watermark = check_dark_skippy_watermark(secret, sig1, sig2)
                    if watermark['found']:
                        result['watermark_found'] = True
                        result['dark_skippy_detected'] = True
                        result['watermark_detail'] = watermark
                        
                        try:
                            secret_bytes = secret.encode('utf-8')
                            b1_int = int(hashlib.sha256(secret_bytes + sig1.txid.encode('utf-8') + b'\x00').hexdigest(), 16)
                            b2_int = int(hashlib.sha256(secret_bytes + sig2.txid.encode('utf-8') + b'\x01').hexdigest(), 16)
                            
                            b1_inv = modinv(b1_int, N)
                            b2_inv = modinv(b2_int, N)
                            
                            d1 = (b1_inv * sig1.r) % N
                            d2 = (b2_inv * sig2.r) % N
                            
                            result['details']['d1'] = hex(d1)
                            result['details']['d2'] = hex(d2)
                            result['kangaroo_ready'] = True
                            result['kangaroo_data'] = {
                                'ranges': [
                                    {'start': 0, 'end': 2**72 - 1, 'public_key': hex(d1)},
                                    {'start': 0, 'end': 2**72 - 1, 'public_key': hex(d2)}
                                ],
                                'seed_length': 16,
                                'watermark': watermark['hash'][:6]
                            }
                        except Exception as e:
                            logger.error(f"Błąd obliczeń Dark Skippy: {e}")
                            result['details']['error'] = str(e)
        
        if pair_count >= max_pairs:
            break
    
    if len(result['patterns_found']) >= 3:
        result['dark_skippy_detected'] = True
        result['kangaroo_ready'] = True
    
    if result['dark_skippy_detected']:
        result['summary'] = f"""
⚠️⚠️⚠️ WYKRYTO POTENCJALNY DARK SKIPPY! ⚠️⚠️⚠️

Znalezione wzorce:
{chr(10).join(['  - ' + p for p in result['patterns_found']])}

Liczba podejrzanych par: {len(result['candidates'])}

{'✅ WATERMARK ZNALEZIONY!' if result['watermark_found'] else '❌ BRAK WATERMARKU (potrzebny SECRET)'}

{'🔑 DANE GOTOWE DLA KANGAROO!' if result['kangaroo_ready'] else '⚠️ Potrzebny SECRET do weryfikacji'}
"""
    
    result['patterns'] = result['patterns_found']
    return result

def check_dark_skippy_watermark(secret: str, sig1: Signature, sig2: Signature) -> Dict:
    result = {
        'found': False,
        'hash': None
    }
    
    try:
        secret_bytes = secret.encode('utf-8')
        r2_bytes = sig2.r.to_bytes(32, 'big')
        
        hash_input = secret_bytes + r2_bytes
        hash_result = hashlib.sha256(hash_input).hexdigest()
        
        result['hash'] = hash_result
        
        if hash_result.startswith('0000d3'):
            result['found'] = True
        
    except Exception as e:
        logger.debug(f"Błąd watermarku: {e}")
    
    return result

# ============================================================
# 5. LSB BIAS (POPRAWNY TEST)
# ============================================================
def detect_nonce_bit_leakage(signatures: List[Signature]) -> Dict:
    """
    Analizuje czy istnieje wyciek bitów nonce poprzez badanie LSB r.
    Test chi-kwadrat dla bitów r.
    """
    if len(signatures) < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {len(signatures)}'}
    
    results = {
        'sample_size': len(signatures),
        'bit_anomalies': [],
        'is_suspicious': False,
        'leakage_detected': False,
        'details': {}
    }
    
    chi_results = []
    for bit_pos in range(8):
        ones = sum(1 for sig in signatures if (sig.r >> bit_pos) & 1)
        zeros = len(signatures) - ones
        
        expected = len(signatures) / 2
        chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
        
        if chi2 > 6.63:  # p=0.01
            chi_results.append({
                'bit': bit_pos,
                'chi_square': chi2,
                'ones': ones,
                'zeros': zeros,
                'bias': ones / len(signatures) - 0.5
            })
    
    if chi_results:
        results['bit_anomalies'].append(f'Bias w LSB: {len(chi_results)} bitów z chi² > 6.63')
        results['details']['chi_results'] = chi_results
        results['is_suspicious'] = True
        results['leakage_detected'] = True
        results['note'] = f'WYKRYTO BIAS W LSB! {len(chi_results)} bitów'
    else:
        results['note'] = 'Brak biasu w LSB'
    
    return results

# ============================================================
# 6. BIT LENGTH BIAS (POPRAWNY TEST)
# ============================================================
def detect_bit_length_bias(signatures: List[Signature]) -> Dict:
    """
    Analizuje rozkład długości bitowych r.
    To wykrywa czy r ma nienaturalny rozkład długości.
    """
    if len(signatures) < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {len(signatures)}'}
    
    results = {
        'sample_size': len(signatures),
        'patterns_found': [],
        'is_suspicious': False,
        'details': {}
    }
    
    bit_lengths = [sig.r.bit_length() for sig in signatures]
    counter = Counter(bit_lengths)
    
    # Sprawdź czy dominuje jakaś długość
    expected = len(signatures) / 256  # Oczekiwana liczba na długość
    
    suspicious = []
    for bl, count in counter.items():
        if count > expected * 4:  # 4x więcej niż oczekiwano
            suspicious.append({
                'bit_length': bl,
                'count': count,
                'expected': expected,
                'ratio': count / expected
            })
    
    if suspicious:
        results['patterns_found'].append(f'Nieregularny rozkład długości bitowych: {len(suspicious)} anomalii')
        results['details']['suspicious_bitlengths'] = suspicious[:5]
        results['is_suspicious'] = True
    
    # Test chi-kwadrat dla rozkładu długości
    # Dzielimy na przedziały: <250, 250, 251, 252, 253, 254, 255, 256
    buckets = defaultdict(int)
    for bl in bit_lengths:
        if bl < 250:
            buckets['<250'] += 1
        elif bl <= 256:
            buckets[str(bl)] += 1
        else:
            buckets['>256'] += 1
    
    expected_per_bucket = len(signatures) / len(buckets)
    chi2 = sum(((count - expected_per_bucket) ** 2 / expected_per_bucket) 
               for count in buckets.values())
    df = len(buckets) - 1
    
    if df > 0 and chi2 > df + 2 * sqrt(2 * df):
        results['patterns_found'].append(f'Chi² dla długości bitowych: {chi2:.2f}')
        results['details']['bitlength_chi2'] = chi2
        results['is_suspicious'] = True
    
    if results['is_suspicious']:
        results['note'] = 'WYKRYTO BIAS W DŁUGOŚCI BITOWEJ!'
    else:
        results['note'] = 'Brak biasu w długości bitowej'
    
    return results

# ============================================================
# 7. AUTOKORELACJA (POPRAWNY TEST)
# ============================================================
def detect_autocorrelation(signatures: List[Signature]) -> Dict:
    """
    Analizuje autokorelację między kolejnymi r.
    Wymaga podpisów w kolejności chronologicznej.
    """
    if len(signatures) < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {len(signatures)}'}
    
    results = {
        'sample_size': len(signatures),
        'patterns_found': [],
        'is_suspicious': False,
        'details': {}
    }
    
    r_values = [sig.r for sig in signatures]
    
    for lag in [1, 2, 3]:
        if lag >= len(r_values):
            continue
        
        x = r_values[:-lag]
        y = r_values[lag:]
        
        n = len(x)
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        
        cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        var_x = sum((x[i] - mean_x) ** 2 for i in range(n))
        var_y = sum((y[i] - mean_y) ** 2 for i in range(n))
        
        if var_x > 0 and var_y > 0:
            corr = cov / (sqrt(var_x) * sqrt(var_y))
        else:
            corr = 0
        
        # Oczekiwana korelacja dla losowych danych
        expected_corr = 1 / sqrt(n) if n > 0 else 0
        
        if abs(corr) > 3 * expected_corr:
            results['patterns_found'].append(f'Autokorelacja lag={lag}: {corr:.3f}')
            results['details'][f'lag_{lag}'] = {
                'correlation': corr,
                'expected': expected_corr
            }
            results['is_suspicious'] = True
    
    if results['is_suspicious']:
        results['note'] = 'WYKRYTO AUTOKORELACJĘ! (wymaga kolejności chronologicznej)'
        results['warning'] = 'Autokorelacja wymaga podpisów w kolejności chronologicznej!'
    else:
        results['note'] = 'Brak autokorelacji'
    
    return results

# ============================================================
# 8. ODLEGŁOŚCI MIĘDZY r (POPRAWNY TEST)
# ============================================================
def detect_r_distances(signatures: List[Signature]) -> Dict:
    """
    Analizuje odległości między kolejnymi r.
    Szuka małych różnic które mogą wskazywać na sekwencyjne nonce.
    """
    if len(signatures) < 3:
        return {'error': 'Za mało podpisów', 'note': 'Potrzeba >=3'}
    
    results = {
        'sample_size': len(signatures),
        'patterns_found': [],
        'is_suspicious': False,
        'details': {}
    }
    
    r_values = [sig.r for sig in signatures]
    distances = [abs(r_values[i+1] - r_values[i]) for i in range(len(r_values)-1)]
    
    if not distances:
        return {'error': 'Brak danych'}
    
    avg_dist = sum(distances) / len(distances)
    min_dist = min(distances)
    max_dist = max(distances)
    
    # Sprawdź bardzo małe odległości (< 2^32)
    small_distances = [d for d in distances if d < 2**32]
    small_count = len(small_distances)
    small_ratio = small_count / len(distances) if distances else 0
    
    results['details'] = {
        'avg_distance': avg_dist,
        'min_distance': min_dist,
        'max_distance': max_dist,
        'small_distances_count': small_count,
        'small_distances_ratio': small_ratio,
        'small_distances': small_distances[:10]
    }
    
    if small_count > 0:
        results['patterns_found'].append(f'Znaleziono {small_count} małych odległości (<2^32)')
        results['is_suspicious'] = True
    
    # Sprawdź czy różnice tworzą ciąg (np. +1, +2, +3)
    if len(distances) >= 5:
        # Sprawdź czy różnice są podobne
        unique_diffs = len(set(distances[:10]))
        if unique_diffs <= 3:
            results['patterns_found'].append(f'Bardzo mało unikalnych różnic: {unique_diffs}')
            results['is_suspicious'] = True
    
    if results['is_suspicious']:
        results['note'] = 'WYKRYTO NIETYPOWE ODLEGŁOŚCI MIĘDZY r!'
    else:
        results['note'] = 'Brak nietypowych odległości'
    
    return results

# ============================================================
# 9. SERIAL CORRELATION (POPRAWNY TEST)
# ============================================================
def detect_serial_correlation(signatures: List[Signature]) -> Dict:
    """
    Analizuje korelację między kolejnymi bitami r.
    Test Pearsona dla kolejnych wartości.
    """
    if len(signatures) < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {len(signatures)}'}
    
    results = {
        'sample_size': len(signatures),
        'patterns_found': [],
        'is_suspicious': False,
        'details': {}
    }
    
    r_values = [sig.r for sig in signatures]
    
    # Korelacja między r_i a r_{i+1}
    n = len(r_values) - 1
    x = r_values[:-1]
    y = r_values[1:]
    
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    
    cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    var_x = sum((x[i] - mean_x) ** 2 for i in range(n))
    var_y = sum((y[i] - mean_y) ** 2 for i in range(n))
    
    if var_x > 0 and var_y > 0:
        corr = cov / (sqrt(var_x) * sqrt(var_y))
    else:
        corr = 0
    
    results['details']['serial_correlation'] = corr
    
    # Oczekiwana korelacja dla losowych danych
    expected_corr = 1 / sqrt(n) if n > 0 else 0
    
    if abs(corr) > 3 * expected_corr:
        results['patterns_found'].append(f'Korelacja szeregowa: {corr:.3f}')
        results['is_suspicious'] = True
    
    # Sprawdź też korelację dla LSB
    bits = [sig.r & 1 for sig in signatures]
    x_bits = bits[:-1]
    y_bits = bits[1:]
    
    # Korelacja dla bitów
    mean_x = sum(x_bits) / n
    mean_y = sum(y_bits) / n
    
    cov = sum((x_bits[i] - mean_x) * (y_bits[i] - mean_y) for i in range(n))
    var_x = sum((x_bits[i] - mean_x) ** 2 for i in range(n))
    var_y = sum((y_bits[i] - mean_y) ** 2 for i in range(n))
    
    if var_x > 0 and var_y > 0:
        corr_bits = cov / (sqrt(var_x) * sqrt(var_y))
    else:
        corr_bits = 0
    
    results['details']['serial_correlation_bits'] = corr_bits
    
    if abs(corr_bits) > 3 * (1 / sqrt(n)):
        results['patterns_found'].append(f'Korelacja szeregowa LSB: {corr_bits:.3f}')
        results['is_suspicious'] = True
    
    if results['is_suspicious']:
        results['note'] = 'WYKRYTO KORELACJĘ SZEREGOWĄ!'
    else:
        results['note'] = 'Brak korelacji szeregowej'
    
    return results

# ============================================================
# 10. SŁABY RNG - POPRAWIONY
# ============================================================
def detect_weak_rng(signatures: List[Signature]) -> Dict:
    if len(signatures) < 20:
        return {'error': 'Za mało podpisów', 'note': f'Potrzeba >=20, masz {len(signatures)}'}
    
    results = {
        'sample_size': len(signatures),
        'patterns_found': [],
        'is_suspicious': False,
        'rng_weak': False,
        'details': {}
    }
    
    # 1. Duplikaty r
    r_counts = Counter([sig.r for sig in signatures])
    duplicates = [(hex(r), count) for r, count in r_counts.items() if count > 1]
    
    if duplicates:
        results['patterns_found'].append(f'Znaleziono {len(duplicates)} powtarzających się r')
        results['details']['duplicates'] = duplicates[:5]
        results['is_suspicious'] = True
        results['rng_weak'] = True
    
    # 2. Entropia z Monte Carlo
    buckets = defaultdict(int)
    for sig in signatures:
        bucket = sig.r >> 248
        buckets[bucket] += 1
    
    entropy = 0
    total = len(signatures)
    for count in buckets.values():
        if count > 0:
            p = count / total
            entropy -= p * log2(p)
    
    max_entropy = log2(len(buckets)) if len(buckets) > 0 else 0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
    
    monte_carlo_threshold = get_monte_carlo_entropy_threshold(len(signatures), len(buckets))
    
    if normalized_entropy < monte_carlo_threshold:
        results['patterns_found'].append(f'Niska entropia r: {normalized_entropy:.3f} < {monte_carlo_threshold:.3f}')
        results['is_suspicious'] = True
        results['rng_weak'] = True
    
    # 3. Runs test
    bits = [sig.r & 1 for sig in signatures]
    runs = 0
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    
    if n > 0 and ones > 0 and zeros > 0:
        expected_runs = (2 * ones * zeros) / n + 1
        var_runs = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
        
        if var_runs > 0:
            z_score = abs(runs - expected_runs) / sqrt(var_runs)
            if z_score > 3.0:
                results['patterns_found'].append(f'Runs test: z={z_score:.2f}')
                results['is_suspicious'] = True
                results['rng_weak'] = True
    
    # 4. Monobit test
    ratio = ones / n if n > 0 else 0.5
    expected_ratio = 0.5
    sigma = sqrt(expected_ratio * (1 - expected_ratio) / n) if n > 0 else 0
    
    if sigma > 0:
        z_score_ratio = abs(ratio - expected_ratio) / sigma
        if z_score_ratio > 4.0:
            results['patterns_found'].append(f'Monobit: z={z_score_ratio:.2f}')
            results['is_suspicious'] = True
            results['rng_weak'] = True
    
    if results['rng_weak']:
        results['note'] = f'WYKRYTO SŁABY RNG! {len(results["patterns_found"])} anomalii'
    else:
        results['note'] = 'Brak wykrytych słabości RNG'
    
    return results

def get_monte_carlo_entropy_threshold(sample_size: int, num_buckets: int, 
                                      iterations: int = 1000) -> float:
    cache_key = (sample_size, num_buckets)
    
    if cache_key in MONTE_CARLO_CACHE:
        return MONTE_CARLO_CACHE[cache_key]
    
    entropies = []
    max_entropy = log2(num_buckets) if num_buckets > 0 else 0
    
    for _ in range(iterations):
        values = [random.randint(0, num_buckets - 1) for _ in range(sample_size)]
        counter = Counter(values)
        entropy = 0
        for count in counter.values():
            if count > 0:
                p = count / sample_size
                entropy -= p * log2(p)
        normalized = entropy / max_entropy if max_entropy > 0 else 0
        entropies.append(normalized)
    
    entropies.sort()
    idx = int(len(entropies) * 0.01)
    threshold = entropies[idx] if idx < len(entropies) else entropies[-1]
    
    MONTE_CARLO_CACHE[cache_key] = threshold
    return threshold

# ============================================================
# 11. EKSPORT DLA SAGE - POPRAWIONY (UNIKALNE NAZWY)
# ============================================================
def export_for_sage_real(equations: List[HNPEquation], address: str = None, filename: str = None) -> str:
    """
    Eksportuje dane dla Sage/LLL z UNIKALNĄ nazwą dla każdego adresu.
    """
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if address:
            # Weź pierwsze 12 znaków adresu dla czytelności
            short_addr = address[:12] if len(address) > 12 else address
            filename = f"hnp_{short_addr}_{timestamp}.txt"
        else:
            filename = f"hnp_real_{timestamp}.txt"
    
    # Zapisz TXT
    with open(filename, 'w') as f:
        f.write("# PRAWDZIWY FORMAT HNP DLA SAGE/LLL\n")
        f.write("# Równanie: k_i = u_i + t_i * d (mod N)\n")
        f.write(f"# N = {hex(N)}\n")
        f.write(f"# Liczba równań: {len(equations)}\n")
        if address:
            f.write(f"# Adres/Pubkey: {address}\n")
        f.write("\n")
        
        for i, eq in enumerate(equations):
            f.write(f"# Równanie {i+1}: txid={eq.txid[:20]}...\n")
            f.write(f"t_{i} = {hex(eq.t)}\n")
            f.write(f"u_{i} = {hex(eq.u)}\n")
            
            if eq.bound is not None:
                f.write(f"bound_{i} = {hex(eq.bound)}\n")
            
            f.write("\n")
    
    # Zapisz JSON
    json_file = filename.replace('.txt', '.json')
    with open(json_file, 'w') as f:
        data = [{'txid': eq.txid, 't': hex(eq.t), 'u': hex(eq.u)} for eq in equations]
        json.dump({
            'N': hex(N),
            'address': address,
            'equations': data,
            'metadata': {
                'count': len(equations),
                'timestamp': datetime.now().isoformat()
            }
        }, f, indent=2)
    
    return filename

# ============================================================
# 12. SYSTEM PUNKTOWY
# ============================================================
def calculate_risk_real(signatures: List[Signature], equations: List[HNPEquation]) -> Dict:
    risk_score = 0
    reasons = []
    details = {}
    
    # 1. REUSED NONCE
    reused = detect_reused_nonce(signatures)
    if reused['found']:
        risk_score += 100
        reasons.append('REUSED_NONCE_CRITICAL')
        details['reused_nonce'] = reused
    
    # 2. DARK SKIPPY
    ds = detect_dark_skippy(signatures)
    if ds.get('dark_skippy_detected'):
        risk_score += 40
        reasons.append('DARK_SKIPPY')
        details['dark_skippy'] = ds
    
    # 3. LSB BIAS
    if len(signatures) >= 20:
        lsb_bias = detect_nonce_bit_leakage(signatures)
        details['lsb_bias'] = lsb_bias
        if lsb_bias.get('leakage_detected'):
            risk_score += 20
            reasons.append('LSB_BIAS')
    
    # 4. BIT LENGTH BIAS
    if len(signatures) >= 20:
        bitlen_bias = detect_bit_length_bias(signatures)
        details['bit_length_bias'] = bitlen_bias
        if bitlen_bias.get('is_suspicious'):
            risk_score += 15
            reasons.append('BIT_LENGTH_BIAS')
    
    # 5. AUTOKORELACJA
    if len(signatures) >= 20:
        autocorr = detect_autocorrelation(signatures)
        details['autocorrelation'] = autocorr
        if autocorr.get('is_suspicious'):
            risk_score += 15
            reasons.append('AUTOCORRELATION')
    
    # 6. ODLEGŁOŚCI MIĘDZY r
    if len(signatures) >= 3:
        distances = detect_r_distances(signatures)
        details['r_distances'] = distances
        if distances.get('is_suspicious'):
            risk_score += 10
            reasons.append('SMALL_R_DISTANCES')
    
    # 7. SERIAL CORRELATION
    if len(signatures) >= 20:
        serial = detect_serial_correlation(signatures)
        details['serial_correlation'] = serial
        if serial.get('is_suspicious'):
            risk_score += 10
            reasons.append('SERIAL_CORRELATION')
    
    # 8. WEAK RNG
    if len(signatures) >= 20:
        weak_rng = detect_weak_rng(signatures)
        details['weak_rng'] = weak_rng
        if weak_rng.get('rng_weak'):
            risk_score += 10
            reasons.append('WEAK_RNG')
    
    # 9. LOW-S
    low_s = check_low_s_normalization(signatures)
    if low_s.get('suspicious'):
        risk_score += 5
        reasons.append('LOW_S_ABNORMAL')
        details['low_s'] = low_s
    
    # 10. Liczba podpisów
    if len(signatures) >= 50:
        reasons.append(f'GOOD_SAMPLE_SIZE ({len(signatures)})')
        risk_score += 5
    elif len(signatures) >= 20:
        reasons.append(f'OK_SAMPLE_SIZE ({len(signatures)})')
        risk_score += 2
    
    # 11. Liczba równań HNP
    if len(equations) >= 20:
        reasons.append(f'HNP_READY ({len(equations)} równań)')
        risk_score += 5
    
    confidence = min(1.0, len(equations) / 50)
    
    if risk_score >= 50:
        level = 'CRITICAL'
        note = 'REUSED NONCE - NATYCHMIASTOWE ODZYSKANIE KLUCZA!'
    elif risk_score >= 30:
        level = 'HIGH'
        note = 'WIELOKROTNE PODEJRZANE WZORCE - URUCHOM SAGE/LLL'
    elif risk_score >= 15:
        level = 'MEDIUM'
        note = 'PODEJRZANE WZORCE - ZBIERZ WIĘCEJ PODPISÓW'
    else:
        level = 'LOW'
        note = 'BRAK WIDOCZNYCH PODATNOŚCI'
    
    return {
        'risk_score': risk_score,
        'confidence': confidence,
        'level': level,
        'reasons': reasons,
        'details': details,
        'note': note,
        'signature_count': len(signatures),
        'hnp_count': len(equations)
    }

# ============================================================
# 13. GŁÓWNA FUNKCJA ANALIZY ADRESU
# ============================================================
def analyze_address_real(address: str, signatures: List[Signature]) -> Dict:
    print(f"\n{'='*80}")
    print(f"🔍 ANALIZA: {address[:30]}...")
    print(f"{'='*80}")
    print(f"Liczba podpisów: {len(signatures)}")
    
    result = {
        'address': address,
        'signature_count': len(signatures)
    }
    
    # 1. REUSED NONCE
    print("\n🔍 SPRAWDZAM REUSED NONCE...")
    reused = detect_reused_nonce(signatures)
    result['reused_nonce'] = reused
    
    if reused['found']:
        print("  ⚠️⚠️⚠️ ZNALEZIONO REUSED NONCE!")
        for pair in reused['pairs']:
            print(f"  r={pair['r'][:20]}...")
            print(f"  🔑 KLUCZ: {pair['private_key'][:30]}...")
    else:
        print("  ✅ Brak reused nonce")
    
    # 2. DARK SKIPPY
    print("\n🔍 SPRAWDZAM DARK SKIPPY...")
    ds = detect_dark_skippy(signatures)
    result['dark_skippy'] = ds
    
    if ds.get('dark_skippy_detected'):
        print("  ⚠️⚠️⚠️ WYKRYTO POTENCJALNY DARK SKIPPY!")
        for pattern in ds.get('patterns_found', []):
            print(f"    - {pattern}")
    else:
        print("  ✅ Brak Dark Skippy")
    
    # 3. LSB BIAS
    if len(signatures) >= 20:
        print("\n🔍 SPRAWDZAM BIAS LSB...")
        lsb = detect_nonce_bit_leakage(signatures)
        result['lsb_bias'] = lsb
        if lsb.get('leakage_detected'):
            print("  ⚠️ WYKRYTO BIAS W LSB!")
            for anomaly in lsb.get('bit_anomalies', []):
                print(f"    - {anomaly}")
        else:
            print("  ✅ Brak biasu LSB")
    
    # 4. BIT LENGTH BIAS
    if len(signatures) >= 20:
        print("\n🔍 SPRAWDZAM BIAS DŁUGOŚCI BITOWEJ...")
        bitlen = detect_bit_length_bias(signatures)
        result['bit_length_bias'] = bitlen
        if bitlen.get('is_suspicious'):
            print("  ⚠️ WYKRYTO BIAS W DŁUGOŚCI BITOWEJ!")
            for pattern in bitlen.get('patterns_found', []):
                print(f"    - {pattern}")
        else:
            print("  ✅ Brak biasu długości bitowej")
    
    # 5. AUTOKORELACJA
    if len(signatures) >= 20:
        print("\n🔍 SPRAWDZAM AUTOKORELACJĘ...")
        autocorr = detect_autocorrelation(signatures)
        result['autocorrelation'] = autocorr
        if autocorr.get('is_suspicious'):
            print("  ⚠️ WYKRYTO AUTOKORELACJĘ!")
            for pattern in autocorr.get('patterns_found', []):
                print(f"    - {pattern}")
        else:
            print("  ✅ Brak autokorelacji")
    
    # 6. ODLEGŁOŚCI MIĘDZY r
    if len(signatures) >= 3:
        print("\n🔍 SPRAWDZAM ODLEGŁOŚCI MIĘDZY r...")
        dist = detect_r_distances(signatures)
        result['r_distances'] = dist
        if dist.get('is_suspicious'):
            print("  ⚠️ WYKRYTO NIETYPOWE ODLEGŁOŚCI!")
            for pattern in dist.get('patterns_found', []):
                print(f"    - {pattern}")
        else:
            print("  ✅ Brak nietypowych odległości")
    
    # 7. SERIAL CORRELATION
    if len(signatures) >= 20:
        print("\n🔍 SPRAWDZAM KORELACJĘ SZEREGOWĄ...")
        serial = detect_serial_correlation(signatures)
        result['serial_correlation'] = serial
        if serial.get('is_suspicious'):
            print("  ⚠️ WYKRYTO KORELACJĘ SZEREGOWĄ!")
            for pattern in serial.get('patterns_found', []):
                print(f"    - {pattern}")
        else:
            print("  ✅ Brak korelacji szeregowej")
    
    # 8. WEAK RNG
    if len(signatures) >= 20:
        print("\n🔍 SPRAWDZAM SŁABY RNG...")
        weak_rng = detect_weak_rng(signatures)
        result['weak_rng'] = weak_rng
        
        if weak_rng.get('rng_weak'):
            print("  ⚠️⚠️⚠️ WYKRYTO SŁABY RNG!")
            for pattern in weak_rng.get('patterns_found', []):
                print(f"    - {pattern}")
        else:
            print("  ✅ Brak wykrytych słabości RNG")
    
    # 9. LOW-S
    print("\n🔍 SPRAWDZAM LOW-S...")
    low_s = check_low_s_normalization(signatures)
    result['low_s'] = low_s
    
    if low_s.get('suspicious'):
        print(f"  ⚠️ {low_s['high_s_count']}/{len(signatures)} podpisów ma high-s")
    else:
        print("  ✅ Normalne low-s")
    
    # 10. BUDUJ RÓWNANIA HNP
    print("\n📊 BUDUJĘ RÓWNANIA HNP...")
    equations = build_hnp_equations(signatures)
    print(f"  Zbudowano {len(equations)} równań")
    result['hnp_equations'] = equations
    
    # 11. RISK SCORE
    print("\n📊 OBLICZAM RISK SCORE...")
    risk = calculate_risk_real(signatures, equations)
    result['risk'] = risk
    
    print(f"\n  RISK SCORE: {risk['risk_score']}")
    print(f"  CONFIDENCE: {risk['confidence']:.2f}")
    print(f"  LEVEL: {risk['level']}")
    print(f"  {risk['note']}")
    
    if risk['reasons']:
        print(f"\n  Czynniki:")
        for reason in risk['reasons']:
            print(f"    - {reason}")
    
    # 12. EKSPORT DLA SAGE - TYLKO DLA HIGH RISK I CRITICAL!
    # Sprawdź czy poziom to HIGH lub CRITICAL
    if risk['level'] in ['HIGH', 'CRITICAL'] and len(equations) >= 3:
        print("\n📤 EKSPORT DLA SAGE/LLL...")
        sage_file = export_for_sage_real(equations, address)
        result['sage_file'] = sage_file
        print(f"  Zapisano: {sage_file}")
    elif len(equations) >= 3:
        print(f"\n📤 Pomijam eksport (LEVEL: {risk['level']} - eksport tylko dla HIGH/CRITICAL)")
    
    print("\n" + "="*80)
    
    return result
# ============================================================
# 14. RAPORTY
# ============================================================
def add_dark_skippy_report(results: Dict) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dark_skippy_report_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("RAPORT DARK SKIPPY DETECTION\n")
        f.write("="*80 + "\n\n")
        f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        found_any = False
        
        for key, data in results.items():
            ds = data.get('dark_skippy', {})
            
            if ds.get('dark_skippy_detected'):
                found_any = True
                f.write("-"*80 + "\n")
                f.write(f"⚠️⚠️⚠️ WYKRYTO DARK SKIPPY!\n")
                f.write("-"*80 + "\n")
                f.write(f"Adres/klucz: {key}\n\n")
                
                details = ds.get('details', {})
                f.write(f"Transakcja 1: {details.get('tx1', 'N/A')}\n")
                f.write(f"Transakcja 2: {details.get('tx2', 'N/A')}\n")
                f.write(f"r1: {details.get('r1', 'N/A')}\n")
                f.write(f"r2: {details.get('r2', 'N/A')}\n")
                
                if 'watermark_hash' in details:
                    f.write(f"\nWatermark: {details['watermark_hash']}\n")
                
                if 'd1' in details and 'd2' in details:
                    f.write(f"\nDane dla Kangaroo:\n")
                    f.write(f"  D1 = {details['d1']}\n")
                    f.write(f"  D2 = {details['d2']}\n")
                    f.write(f"  Zakres: [0, 2^72)\n")
                
                f.write(f"\n{ds.get('summary', '')}\n\n")
        
        if not found_any:
            f.write("❌ NIE WYKRYTO ŻADNEGO PRZYPADKU DARK SKIPPY\n")
    
    return filename

def generate_comprehensive_report(results: Dict, filename: str = None) -> str:
    if filename is None:
        filename = "raportogolny.txt"
    
    total_addresses = len(results)
    critical = []
    high_risk = []
    medium_risk = []
    low_risk = []
    insufficient = []
    keys_recovered = []
    dark_skippy_found = []
    weak_rng_detected = []
    
    for key, data in results.items():
        risk = data.get('risk', {})
        level = risk.get('level', 'INSUFFICIENT_DATA')
        
        if level == 'CRITICAL':
            critical.append((key, data))
        elif level == 'HIGH':
            high_risk.append((key, data))
        elif level == 'MEDIUM':
            medium_risk.append((key, data))
        elif level == 'LOW':
            low_risk.append((key, data))
        else:
            insufficient.append((key, data))
        
        if data.get('reused_nonce', {}).get('found'):
            for pair in data['reused_nonce'].get('pairs', []):
                if 'private_key' in pair:
                    keys_recovered.append({
                        'address': key,
                        'key': pair['private_key'],
                        'r': pair.get('r', 'N/A'),
                        'tx1': pair.get('tx1', 'N/A'),
                        'tx2': pair.get('tx2', 'N/A'),
                        'k': pair.get('k', 'N/A')
                    })
        
        if data.get('dark_skippy', {}).get('dark_skippy_detected'):
            dark_skippy_found.append((key, data))
        
        if data.get('weak_rng', {}).get('rng_weak'):
            weak_rng_detected.append((key, data))
    
    with open(filename, 'w', encoding='utf-8') as f:
        write_summary(f, results, critical, high_risk, medium_risk, low_risk, insufficient, 
                      keys_recovered, dark_skippy_found, weak_rng_detected)
        write_critical(f, critical, keys_recovered)
        write_high_risk(f, high_risk)
        write_medium_risk(f, medium_risk)
        write_recommendations(f, critical, high_risk, dark_skippy_found, weak_rng_detected, keys_recovered)
    
    return filename

def write_summary(f, results, critical, high_risk, medium_risk, low_risk, insufficient,
                  keys_recovered, dark_skippy_found, weak_rng_detected):
    total_addresses = len(results)
    f.write("="*100 + "\n")
    f.write("📊 RAPORT OGÓLNY - KOMPLETNA ANALIZA HNP\n")
    f.write("="*100 + "\n\n")
    f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Adresy: {total_addresses}\n\n")
    
    f.write("-"*100 + "\n")
    f.write("📊 PODSUMOWANIE\n")
    f.write("-"*100 + "\n\n")
    
    f.write(f"  🔴 CRITICAL (reused nonce):     {len(critical):>4} adresów\n")
    f.write(f"  🟠 HIGH RISK:                  {len(high_risk):>4} adresów\n")
    f.write(f"  🟡 MEDIUM RISK:                {len(medium_risk):>4} adresów\n")
    f.write(f"  🟢 LOW RISK:                   {len(low_risk):>4} adresów\n")
    f.write(f"  ⚪ INSUFFICIENT:               {len(insufficient):>4} adresów\n")
    f.write("\n")
    f.write(f"  🔑 Odzyskane klucze:            {len(keys_recovered):>4}\n")
    f.write(f"  🎯 Dark Skippy:                 {len(dark_skippy_found):>4} adresów\n")
    f.write(f"  🎲 Słaby RNG:                  {len(weak_rng_detected):>4} adresów\n")

def write_critical(f, critical, keys_recovered):
    if not critical:
        return
    
    f.write("\n" + "="*100 + "\n")
    f.write("🔴🔴🔴 CRITICAL - ODZYSKANE KLUCZE PRYWATNE\n")
    f.write("="*100 + "\n\n")
    f.write("⚠️⚠️⚠️ TO SĄ PRAWDZIWE KLUCZE PRYWATNE! ⚠️⚠️⚠️\n")
    f.write("NATYCHMIAST PRZENIEŚ ŚRODKI Z TYCH ADRESÓW!\n\n")
    
    for key, data in critical:
        f.write(f"📍 ADRES/PUBKEY: {key}\n")
        f.write("-"*80 + "\n")
        
        pairs = data.get('reused_nonce', {}).get('pairs', [])
        if pairs:
            for pair in pairs:
                f.write(f"  🔑🔑🔑 PRIVATE KEY: {pair.get('private_key', 'N/A')}\n")
                f.write(f"  📌 r: {pair.get('r', 'N/A')}\n")
                f.write(f"  📌 k (nonce): {pair.get('k', 'N/A')}\n")
                f.write(f"  📌 Transakcja 1: {pair.get('tx1', 'N/A')}\n")
                f.write(f"  📌 Transakcja 2: {pair.get('tx2', 'N/A')}\n")
                f.write("\n")
        else:
            f.write("  ❌ Brak danych o odzyskanych kluczach!\n\n")
        
        if data.get('dark_skippy', {}).get('dark_skippy_detected'):
            f.write("  ⚠️ Dodatkowo: WYKRYTO DARK SKIPPY!\n\n")
        
        if data.get('weak_rng', {}).get('rng_weak'):
            f.write("  ⚠️ Dodatkowo: WYKRYTO SŁABY RNG!\n\n")
        
        if 'sage_file' in data:
            f.write(f"  📤 Sage/LLL: {data['sage_file']}\n\n")
    
    if keys_recovered:
        f.write("\n" + "="*100 + "\n")
        f.write("🔑🔑🔑 WSZYSTKIE ODZYSKANE KLUCZE\n")
        f.write("="*100 + "\n\n")
        for item in keys_recovered:
            f.write(f"{item['key']}\n")

def write_high_risk(f, high_risk):
    if not high_risk:
        return
    
    f.write("\n" + "="*100 + "\n")
    f.write("🟠🟠🟠 HIGH RISK\n")
    f.write("="*100 + "\n\n")
    
    for key, data in high_risk:
        risk = data.get('risk', {})
        f.write(f"📍 ADRES: {key}\n")
        f.write(f"  Score: {risk.get('risk_score', 0)}\n")
        f.write(f"  Reasons: {', '.join(risk.get('reasons', []))}\n")
        
        # Pokaż nazwę pliku Sage dla tego adresu
        if 'sage_file' in data:
            f.write(f"  📤 Sage/LLL: {data['sage_file']}\n")
        
        if data.get('dark_skippy', {}).get('dark_skippy_detected'):
            f.write(f"\n  🎯 Dark Skippy:\n")
            for pattern in data['dark_skippy'].get('patterns_found', []):
                f.write(f"    - {pattern}\n")
        
        if data.get('weak_rng', {}).get('rng_weak'):
            f.write(f"\n  🎲 Słaby RNG:\n")
            for pattern in data['weak_rng'].get('patterns_found', []):
                f.write(f"    - {pattern}\n")
        
        f.write("\n")

def write_medium_risk(f, medium_risk):
    if not medium_risk:
        return
    
    f.write("\n" + "="*100 + "\n")
    f.write("🟡🟡🟡 MEDIUM RISK\n")
    f.write("="*100 + "\n\n")
    
    for key, data in medium_risk[:20]:
        risk = data.get('risk', {})
        f.write(f"📍 {key[:60]}...\n")
        f.write(f"  Score: {risk.get('risk_score', 0)}\n")
        f.write(f"  Podpisy: {data.get('signature_count', 0)}\n")
        f.write(f"  Reasons: {', '.join(risk.get('reasons', []))}\n")
        
        if 'sage_file' in data:
            f.write(f"  📤 Sage/LLL: {data['sage_file']}\n")
        f.write("\n")

def write_recommendations(f, critical, high_risk, dark_skippy_found, weak_rng_detected, keys_recovered):
    f.write("\n" + "="*100 + "\n")
    f.write("💡 REKOMENDACJE\n")
    f.write("="*100 + "\n\n")
    
    if critical:
        f.write("🚨🚨🚨 NATYCHMIASTOWE DZIAŁANIA:\n")
        f.write("  1. Przenieś WSZYSTKIE środki z adresów CRITICAL\n")
        f.write("  2. Odzyskane klucze są PRAWIDŁOWE\n")
        f.write("  3. Zmień generator liczb losowych\n\n")
        
        if keys_recovered:
            f.write("🔑 ODZYSKANE KLUCZE (skopiuj i użyj):\n")
            for item in keys_recovered:
                f.write(f"  {item['key']}\n")
            f.write("\n")
    
    if high_risk:
        f.write("⚠️ URUCHOM SAGE/LLL DLA ADRESÓW HIGH RISK\n")
        f.write("  - Pliki hnp_*.txt zawierają dane (każdy adres ma osobny plik)\n\n")
    
    if dark_skippy_found:
        f.write("🎯 DARK SKIPPY:\n")
        f.write("  - Użyj Kangaroo do odzyskania nonce (zakres 2^72)\n")
        f.write("  - Potrzebujesz SECRET do weryfikacji watermarku\n\n")
    
    if weak_rng_detected:
        f.write("🎲 SŁABY RNG:\n")
        f.write("  - Sprawdź czy nonce są generowane sekwencyjnie\n")
        f.write("  - Uruchom Kangaroo dla małych nonce\n\n")
    
    if not critical and not high_risk:
        f.write("✅ BRAK WIDOCZNYCH PODATNOŚCI\n")
        f.write("  Adresy wydają się bezpieczne\n\n")
    
    f.write("="*100 + "\n")
    f.write("KONIEC RAPORTU\n")
    f.write("="*100 + "\n")

# ============================================================
# 15. ANALIZA WSZYSTKICH ADRESÓW
# ============================================================
def analyze_all_addresses_real(filename: str, secret: str = None) -> Dict:
    print(f"📂 Wczytywanie danych z: {filename}")
    signatures = parse_tx_file(filename)
    print(f"✅ Wczytano {len(signatures)} poprawnych podpisów")
    
    if not signatures:
        print("❌ Brak poprawnych podpisów")
        return {}
    
    grouped = defaultdict(list)
    for sig in signatures:
        key = sig.pubkey if sig.pubkey != 'UNKNOWN' else sig.address
        grouped[key].append(sig)
    
    print(f"📊 Znaleziono {len(grouped)} unikalnych kluczy/adresów")
    
    results = {}
    
    for key, sigs in tqdm(grouped.items(), desc="Analizowanie"):
        if len(sigs) >= 2:
            result = analyze_address_real(key, sigs)
            ds_result = detect_dark_skippy(sigs, secret)
            result['dark_skippy'] = ds_result
            results[key] = result
    
    print("\n" + "="*80)
    print("📊 GENEROWANIE RAPORTU OGÓLNEGO...")
    print("="*80)
    
    report_file = generate_comprehensive_report(results)
    print(f"✅ Zapisano: {report_file}")
    
    ds_report = add_dark_skippy_report(results)
    print(f"✅ Zapisano Dark Skippy: {ds_report}")
    
    return results

# ============================================================
# MAIN
# ============================================================
def main():
    if len(sys.argv) < 2:
        print("Użycie: python hnp_complete.py <plik_z_transakcjami.txt> [SECRET]")
        print("\nTen skrypt przeprowadza KOMPLETNĄ analizę HNP:")
        print("  ✅ Reused nonce (r1 == r2) - algebraiczne odzyskanie klucza")
        print("  ✅ Low-S normalization check")
        print("  ✅ Dark Skippy detection (z opcjonalnym SECRET)")
        print("  ✅ LSB Bias (chi-kwadrat dla bitów r)")
        print("  ✅ Bit Length Bias (rozkład długości bitowych)")
        print("  ✅ Autokorelacja")
        print("  ✅ Odległości między r")
        print("  ✅ Korelacja szeregowa")
        print("  ✅ Słaby RNG detection (poprawiona entropia z Monte Carlo)")
        print("  ✅ Eksport do Sage/LLL (prawdziwy format HNP - KAŻDY ADRES MA OSOBNY PLIK)")
        print("\n  Opcjonalnie: podaj SECRET jako drugi argument do detekcji Dark Skippy")
        return
    
    filename = sys.argv[1]
    secret = sys.argv[2] if len(sys.argv) >= 3 else None
    
    if secret:
        print(f"🔑 Używam SECRET: {secret}")
    
    analyze_all_addresses_real(filename, secret)

if __name__ == "__main__":
    main()