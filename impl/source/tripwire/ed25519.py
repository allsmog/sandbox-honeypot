"""Ed25519 public-key derivation in pure Python (RFC 8032, section 5.1.5)."""

import hashlib

_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_BASE = (_BX, _BY, 1, (_BX * _BY) % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar, point):
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode(point):
    x, y, z, _ = point
    inverse = pow(z, _P - 2, _P)
    x = x * inverse % _P
    y = y * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_key(private_seed):
    """Return the 32-byte public key for a 32-byte RFC 8032 private key."""
    assert len(private_seed) == 32, "ed25519 private key must be 32 bytes"
    digest = hashlib.sha512(private_seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= ~7
    scalar &= ~(1 << 255)
    scalar |= 1 << 254
    return _encode(_multiply(scalar, _BASE))
