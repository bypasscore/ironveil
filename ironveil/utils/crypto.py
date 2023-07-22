"""
IronVeil Crypto Utilities

Token entropy analysis, HMAC chain verification, weak PRNG detection,
hash identification, and JWT analysis for casino platform security audits.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import re
import struct
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.utils.crypto")


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def analyze_token_entropy(token: str) -> Dict[str, Any]:
    """Analyze a token's entropy and randomness quality."""
    entropy = shannon_entropy(token)
    length = len(token)
    total_bits = entropy * length

    # Determine character set
    charset_size = len(set(token))
    max_entropy = math.log2(charset_size) if charset_size > 1 else 0
    efficiency = entropy / max_entropy if max_entropy > 0 else 0

    quality = "STRONG"
    if total_bits < 64:
        quality = "WEAK"
    elif total_bits < 128:
        quality = "MODERATE"

    return {
        "length": length,
        "entropy_per_char": round(entropy, 4),
        "total_entropy_bits": round(total_bits, 1),
        "charset_size": charset_size,
        "max_entropy_per_char": round(max_entropy, 4),
        "efficiency": round(efficiency, 4),
        "quality": quality,
    }


def verify_hmac_chain(
    tokens: List[str],
    secret: Optional[str] = None,
    algorithm: str = "sha256",
) -> Dict[str, Any]:
    """Verify an HMAC chain where each token is the HMAC of the next."""
    if len(tokens) < 2:
        return {"valid": False, "error": "Need at least 2 tokens"}

    hash_func = getattr(hashlib, algorithm, None)
    if hash_func is None:
        return {"valid": False, "error": f"Unknown algorithm: {algorithm}"}

    # If no secret, check if each token is the hash of the next
    breaks: List[int] = []
    for i in range(len(tokens) - 1):
        if secret:
            expected = hmac.new(secret.encode(), tokens[i + 1].encode(), hash_func).hexdigest()
        else:
            expected = hash_func(tokens[i + 1].encode()).hexdigest()

        if tokens[i] != expected:
            breaks.append(i)

    return {
        "valid": len(breaks) == 0,
        "chain_length": len(tokens),
        "algorithm": algorithm,
        "breaks_at": breaks,
        "verified_links": len(tokens) - 1 - len(breaks),
    }


def detect_weak_prng(samples: List[int]) -> Dict[str, Any]:
    """Detect signs of weak or predictable PRNG usage.

    Checks for:
    - Linear congruential generator patterns
    - Timestamp-based seeding artifacts
    - Low entropy sequences
    - Repeated subsequences
    """
    n = len(samples)
    if n < 10:
        return {"error": "Need at least 10 samples"}

    findings: List[str] = []
    is_weak = False

    # Check for LCG pattern: x[n+1] = (a*x[n] + c) mod m
    if n >= 5:
        diffs = [samples[i + 1] - samples[i] for i in range(min(n - 1, 100))]
        second_diffs = [diffs[i + 1] - diffs[i] for i in range(len(diffs) - 1)]
        if len(set(second_diffs)) <= 3:
            findings.append("Possible linear congruential generator pattern detected")
            is_weak = True

    # Check for repeated values (birthday paradox)
    unique_ratio = len(set(samples)) / n
    if unique_ratio < 0.5 and n > 100:
        findings.append(f"High collision rate: {unique_ratio:.2%} unique values")
        is_weak = True

    # Check for sequential patterns
    sequential = sum(
        1 for i in range(n - 1) if samples[i + 1] == samples[i] + 1
    )
    if sequential / max(n - 1, 1) > 0.3:
        findings.append(f"Sequential pattern: {sequential}/{n-1} consecutive increments")
        is_weak = True

    # Entropy analysis
    as_bytes = b"".join(
        struct.pack(">I", s & 0xFFFFFFFF) for s in samples[:250]
    )
    byte_entropy = shannon_entropy(as_bytes.hex())
    if byte_entropy < 3.0:
        findings.append(f"Low byte entropy: {byte_entropy:.2f} bits/char")
        is_weak = True

    # Repeated subsequences
    subseq_len = 3
    subsequences = [
        tuple(samples[i:i + subseq_len])
        for i in range(n - subseq_len + 1)
    ]
    subseq_counts = Counter(subsequences)
    repeated = sum(1 for c in subseq_counts.values() if c > 2)
    if repeated > len(subseq_counts) * 0.1 and n > 100:
        findings.append(f"Excessive repeated subsequences: {repeated}")
        is_weak = True

    return {
        "is_weak": is_weak,
        "sample_size": n,
        "unique_ratio": round(unique_ratio, 4),
        "byte_entropy": round(byte_entropy, 4),
        "findings": findings,
    }


def identify_hash(hash_str: str) -> List[str]:
    """Identify possible hash algorithms from a hex string."""
    length = len(hash_str)
    candidates: List[str] = []

    hash_lengths = {
        32: ["MD5", "NTLM"],
        40: ["SHA-1", "RIPEMD-160"],
        56: ["SHA-224"],
        64: ["SHA-256", "BLAKE2s-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "SHA-512/256", "BLAKE2b-512", "Whirlpool"],
    }

    if re.match(r"^[a-fA-F0-9]+$", hash_str):
        if length in hash_lengths:
            candidates.extend(hash_lengths[length])
        if hash_str.startswith("$2") and length > 50:
            candidates.append("bcrypt")
    elif hash_str.startswith("$argon2"):
        candidates.append("Argon2")
    elif hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
        candidates.append("bcrypt")
    elif hash_str.startswith("$6$"):
        candidates.append("SHA-512crypt")
    elif hash_str.startswith("$5$"):
        candidates.append("SHA-256crypt")

    return candidates


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode a JWT token (without verification) and analyze its structure."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT format (expected 3 parts)"}

    try:
        header_raw = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw))
    except Exception as exc:
        return {"error": f"Failed to decode header: {exc}"}

    try:
        payload_raw = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_raw))
    except Exception as exc:
        return {"error": f"Failed to decode payload: {exc}"}

    analysis: Dict[str, Any] = {
        "header": header,
        "payload": payload,
        "algorithm": header.get("alg", "unknown"),
        "token_type": header.get("typ", "unknown"),
    }

    # Security checks
    warnings: List[str] = []
    alg = header.get("alg", "")
    if alg == "none":
        warnings.append("CRITICAL: Algorithm set to 'none' — signature not verified")
    if alg in ("HS256", "HS384", "HS512"):
        warnings.append("HMAC algorithm — vulnerable to key confusion attacks if RSA expected")
    if "exp" not in payload:
        warnings.append("No expiration claim (exp) — token never expires")
    if "iat" not in payload:
        warnings.append("No issued-at claim (iat)")
    if "jti" not in payload:
        warnings.append("No JWT ID (jti) — replay attacks possible")

    analysis["warnings"] = warnings
    analysis["signature_b64"] = parts[2][:20] + "..."

    return analysis


def compare_timing_safe(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0
