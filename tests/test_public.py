import pytest

from ed25519v.verify import (
    L,
    check_canonical,
    decode_point,
    decode_scalar,
    sig_batch,
    verify,
)

BASE_ENCODING = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)
IDENTITY = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
)
NONCANONICAL_IDENTITY = bytes.fromhex(
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)
PK_A = bytes.fromhex(
    "c20df4ff95c8b7026e73830a97f9296a91e4acc7c98a418b186a16a4621735c3"
)
PK_B = bytes.fromhex(
    "5a350c0b7eab1bcd693030b4fced5d10caf13297a1c02fd4f959d6f6bc101744"
)
SIG_A = bytes.fromhex(
    "2bccac14fee704375b8a43aa08106c4205625dc837a3dcc4fd83b36dfd80db0c"
    "ab23e9028662f1ba2590e9705c11ef3dd0c5a3fb9b4985b9c30320c14acfc30b"
)
MESSAGE = b"batch message"
POLICY = {
    "reject_small_order": True,
    "canonical_encoding": True,
    "hash_alg": "sha512",
}


def test_valid_point_decodes_and_noncanonical_form_is_rejected():
    point = decode_point(BASE_ENCODING)
    assert isinstance(point, tuple)
    assert len(point) == 4
    with pytest.raises(ValueError):
        decode_point(NONCANONICAL_IDENTITY)


def test_scalar_decoder_enforces_group_order():
    assert decode_scalar((L - 1).to_bytes(32, "little")) == L - 1
    with pytest.raises(ValueError):
        decode_scalar(L.to_bytes(32, "little"))


def test_canonical_check_rejects_alternate_encoding():
    point = decode_point(IDENTITY)
    assert check_canonical(IDENTITY, point) is True
    assert check_canonical(NONCANONICAL_IDENTITY, point) is False


def test_verify_rejects_small_order_public_key():
    signature = BASE_ENCODING + (1).to_bytes(32, "little")
    assert verify(IDENTITY, b"attack", signature) is False


def test_batch_keeps_two_signatures_independent():
    items = [
        {"public_key": PK_A, "message": MESSAGE, "signature": SIG_A},
        {"public_key": PK_B, "message": MESSAGE, "signature": SIG_A},
    ]
    report = sig_batch(items, POLICY)
    assert report["results"] == [True, False]
    assert report["all_valid"] is False