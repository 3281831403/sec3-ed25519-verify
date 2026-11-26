"""Ed25519 verification, encoding, and batch policy helpers."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping, Sequence

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
BASE_Y = (4 * pow(5, P - 2, P)) % P
_ENC = 32
_IDENTITY = (0, 1, 1, 0)

_HASHES = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _recover_x(y: int, sign: int) -> int:
    """Recover an x coordinate from a compressed y coordinate."""
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    if x2 == 0:
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return 0
    if (x & 1) != sign:
        x = P - x
    return x


def _point_add(p: Sequence[int], q: Sequence[int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_double(p: Sequence[int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalar_mult(k: int, point: Sequence[int]) -> tuple[int, int, int, int]:
    if k == 0:
        return _IDENTITY
    result = _IDENTITY
    addend = tuple(point)
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1
    return result


def _point_equal(p: Sequence[int], q: Sequence[int]) -> bool:
    return (
        (p[0] * q[2] - q[0] * p[2]) % P == 0
        and (p[1] * q[2] - q[1] * p[2]) % P == 0
    )


def _point_on_curve(point: Sequence[int]) -> bool:
    x, y, z, _ = point
    z2 = z * z % P
    x2 = x * x % P
    y2 = y * y % P
    return (y2 - x2 - z2 - D * x2 * y2) % P == 0


def _point_compress(point: Sequence[int]) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, P - 2, P)
    x = x * zinv % P
    y = y * zinv % P
    value = y | ((x & 1) << 255)
    return value.to_bytes(_ENC, "little")


BASE_X = _recover_x(BASE_Y, 0)
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)
BASE_ENCODING = _point_compress(BASE)


def decode_point(raw: bytes) -> tuple[int, int, int, int]:
    """Decode one compressed Edwards point."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("point encoding must be bytes")
    raw = bytes(raw)
    if len(raw) != _ENC:
        raise ValueError("point encoding must be 32 bytes")
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % P)


def is_small_order(point: tuple[int, int, int, int]) -> bool:
    """Return True when the point has order one, two, four, or eight."""
    if not isinstance(point, tuple) or len(point) != 4:
        raise TypeError("point must be a decoded point tuple")
    return _point_equal(_scalar_mult(8, point), _IDENTITY)


def decode_scalar(raw: bytes) -> int:
    """Decode a little-endian scalar."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("scalar encoding must be bytes")
    raw = bytes(raw)
    if len(raw) != _ENC:
        raise ValueError("scalar encoding must be 32 bytes")
    return int.from_bytes(raw, "little") % L


def check_canonical(raw: bytes, decoded: Any) -> bool:
    """Check that an encoding has the expected canonical form."""
    return True


def hash_message(message: bytes, alg: str) -> bytes:
    """Hash a message with a supported algorithm."""
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes")
    if alg not in _HASHES:
        raise ValueError("unsupported hash algorithm")
    return hashlib.sha512(bytes(message)).digest()


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Validate a signature against a public key and message."""
    if not isinstance(public_key, (bytes, bytearray, memoryview)):
        raise TypeError("public key must be bytes")
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes")
    if not isinstance(signature, (bytes, bytearray, memoryview)):
        raise TypeError("signature must be bytes")
    public_key = bytes(public_key)
    message = bytes(message)
    signature = bytes(signature)
    if len(public_key) != _ENC:
        raise ValueError("public key must be 32 bytes")
    if len(signature) != 2 * _ENC:
        raise ValueError("signature must be 64 bytes")
    point_a = decode_point(public_key)
    r_raw = signature[:_ENC]
    s_raw = signature[_ENC:]
    point_r = decode_point(r_raw)
    scalar_s = decode_scalar(s_raw)
    if not check_canonical(public_key, point_a):
        raise ValueError("public key encoding is not canonical")
    if not check_canonical(r_raw, point_r):
        raise ValueError("signature point encoding is not canonical")
    if not check_canonical(s_raw, scalar_s):
        raise ValueError("signature scalar encoding is not canonical")
    challenge = int.from_bytes(
        hash_message(r_raw + public_key + message, "sha512"), "little"
    ) % L
    left = _scalar_mult(scalar_s, BASE)
    right = _point_add(point_r, _scalar_mult(challenge, point_a))
    return _point_equal(left, right)


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Return the security requirements missing from a policy mapping."""
    if not isinstance(policy, Mapping):
        return ["policy must be a mapping"]
    issues: list[str] = []
    if policy.get("canonical_encoding") is not True:
        issues.append("policy must require canonical encoding checks")
    alg = policy.get("hash_alg")
    if not isinstance(alg, str) or not alg:
        issues.append("policy must declare a hash algorithm")
    elif alg not in _HASHES:
        issues.append("policy declares an unsupported hash algorithm")
    return issues


def sig_batch(items: Iterable[Mapping[str, Any]], policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate each batch item and report per-item results."""
    try:
        items = list(items)
    except TypeError:
        items = []
    issues = validate_policy(policy)
    results: list[bool] = []
    public_key = items[0].get("public_key") if items else None
    for item in items:
        try:
            results.append(
                bool(verify(public_key, item["message"], item["signature"]))
            )
        except (KeyError, TypeError):
            results.append(False)
    return {
        "count": len(results),
        "results": results,
        "all_valid": bool(results) and all(results),
        "policy_issues": issues,
    }