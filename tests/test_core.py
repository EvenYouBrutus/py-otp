"""Tests for otp_text.core."""

import pytest

from otp_text import (
    decrypt,
    describe_key,
    encrypt,
    generate_key,
    key_for,
    symbols_to_text,
    text_to_symbols,
)
from otp_text.core import MODULUS, TOKEN_WIDTH


# ---------- round-trip ----------

@pytest.mark.parametrize("msg", [
    "",
    "a",
    "hello",
    "Hello, 世界! 🌍",
    "line1\nline2\ttabbed",
    "😀" * 100,
])
def test_roundtrip(msg):
    key = generate_key(max(len(msg), 1))
    ct = encrypt(msg, key)
    assert decrypt(ct, key) == msg


def test_roundtrip_with_oversized_key():
    msg = "hello"
    key = generate_key(50)
    assert decrypt(encrypt(msg, key), key) == msg


# ---------- key generation ----------

def test_generate_key_length():
    k = generate_key(7)
    assert len(k.split()) == 7


def test_generate_key_unique():
    assert generate_key(20) != generate_key(20)


def test_generate_key_rejects_zero():
    with pytest.raises(ValueError):
        generate_key(0)


def test_generate_key_rejects_negative():
    with pytest.raises(ValueError):
        generate_key(-1)


def test_generate_key_rejects_non_int():
    with pytest.raises(ValueError):
        generate_key("5")  # type: ignore[arg-type]


def test_key_for_size():
    assert len(key_for("hello").split()) == 5


# ---------- encrypt / decrypt validation ----------

def test_encrypt_rejects_short_key():
    with pytest.raises(ValueError, match="Key too short"):
        encrypt("hello", generate_key(3))


def test_decrypt_rejects_short_key():
    ct = encrypt("hello", generate_key(5))
    with pytest.raises(ValueError, match="Key too short"):
        decrypt(ct, generate_key(3))


def test_encrypt_rejects_non_str_plaintext():
    with pytest.raises(TypeError):
        encrypt(b"hello", generate_key(5))  # type: ignore[arg-type]


def test_encrypt_rejects_non_str_key():
    with pytest.raises(TypeError):
        encrypt("hello", 123)  # type: ignore[arg-type]


def test_decrypt_rejects_non_str_ciphertext():
    with pytest.raises(TypeError):
        decrypt(b"abc", generate_key(3))  # type: ignore[arg-type]


def test_decrypt_rejects_malformed_ciphertext():
    with pytest.raises(ValueError, match="Invalid hex token"):
        decrypt("zzzzzz", generate_key(1))


# ---------- serialization ----------

def test_symbols_to_text_format():
    assert symbols_to_text([0, 1, 0x10FFFF]) == "000000 000001 10ffff"


def test_symbols_to_text_token_width():
    for tok in symbols_to_text([1, 255, 65535]).split():
        assert len(tok) == TOKEN_WIDTH


def test_symbols_to_text_rejects_out_of_range():
    with pytest.raises(ValueError):
        symbols_to_text([MODULUS])


def test_text_to_symbols_roundtrip():
    symbols = [0, 1, 12345, MODULUS - 1]
    assert text_to_symbols(symbols_to_text(symbols)) == symbols


def test_text_to_symbols_rejects_bad_hex():
    with pytest.raises(ValueError, match="Invalid hex token"):
        text_to_symbols("nothex")


def test_text_to_symbols_rejects_out_of_range():
    with pytest.raises(ValueError, match="out of range"):
        text_to_symbols("ffffff")  # 0xFFFFFF > 0x10FFFF


# ---------- describe_key ----------

def test_describe_key_valid():
    info = describe_key(generate_key(5))
    assert info["valid"] is True
    assert info["length"] == 5
    assert info["error"] is None


def test_describe_key_invalid():
    info = describe_key("zzz")
    assert info["valid"] is False
    assert info["error"] is not None


def test_describe_key_non_str():
    info = describe_key(None)  # type: ignore[arg-type]
    assert info["valid"] is False


# ---------- ciphertext properties ----------

def test_ciphertext_differs_from_plaintext():
    msg = "secret message"
    key = key_for(msg)
    assert encrypt(msg, key) != msg


def test_two_ciphertexts_differ_with_different_keys():
    msg = "same message"
    ct1 = encrypt(msg, key_for(msg))
    ct2 = encrypt(msg, key_for(msg))
    assert ct1 != ct2