"""
One-Time Pad (OTP) — text-only library.

Pure text in / text out. No files, no binary blobs. Everything the
caller needs to persist is a printable string (hex tokens).

Security rules (Shannon):
    1. Key must be truly random      -> we use `secrets`.
    2. Key must be >= message length -> enforced by every function.
    3. Key must be used only once    -> caller's responsibility.
    4. Key must stay secret          -> caller's responsibility.

Public API:
    generate_key(length)             -> str   (hex token string)
    encrypt(plaintext, key)          -> str   (ciphertext hex tokens)
    decrypt(ciphertext, key)         -> str   (plaintext)
    key_for(plaintext)               -> str   (convenience: key sized to msg)
    describe_key(key)                -> dict  (metadata about a key string)
"""

import secrets


# ============================================================
# CONSTANTS
# ============================================================

# Size of the Unicode code-point space: 0x000000 .. 0x10FFFF.
# Every plaintext char, key symbol and ciphertext symbol lives in this range.
MODULUS = 0x110000

# Fixed width for each hex token, so the serialized strings line up
# and are easy to eyeball / split.
TOKEN_WIDTH = 6

__all__ = [
    "generate_key",
    "key_for",
    "encrypt",
    "decrypt",
    "describe_key",
    "symbols_to_text",
    "text_to_symbols",
]


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _symbols_to_text(symbols: list[int]) -> str:
    """
    Serializes integer symbols into a space-separated hex-token string.

    Parameters:
        symbols (list[int]): values in [0, MODULUS).

    Returns:
        str: e.g. "00a1f3 10ffff 000001".

    Raises:
        ValueError: if any symbol is outside [0, MODULUS).
    """
    for s in symbols:
        if not (0 <= s < MODULUS):
            raise ValueError(f"Symbol out of range: {s}")
    return " ".join(f"{s:0{TOKEN_WIDTH}x}" for s in symbols)


def _text_to_symbols(text: str) -> list[int]:
    """
    Parses a whitespace-separated hex-token string into integer symbols.

    Parameters:
        text (str): tokens produced by `_symbols_to_text`.

    Returns:
        list[int]: parsed symbols.

    Raises:
        ValueError: on malformed input (non-hex token or out-of-range value).
    """
    tokens = text.split()
    result: list[int] = []
    for tok in tokens:
        try:
            value = int(tok, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid hex token: {tok!r}") from exc
        if not (0 <= value < MODULUS):
            raise ValueError(f"Symbol out of range: {tok!r}")
        result.append(value)
    return result


def _key_symbols(key: str) -> list[int]:
    """
    Internal: parses a key string into a list of integer key symbols.
    """
    return _text_to_symbols(key)


# ============================================================
# PUBLIC API
# ============================================================

def generate_key(length: int) -> str:
    """
    Generates a random OTP key of `length` symbols and returns it as a
    printable hex-token string.

    Each symbol is drawn uniformly from [0, MODULUS) using
    `secrets.randbelow` — a cryptographically secure RNG backed by
    os.urandom. Never use `random` for this.

    Parameters:
        length (int): number of key symbols. Must equal or exceed the
                      length of the message you intend to encrypt.

    Returns:
        str: space-separated hex tokens.

    Raises:
        ValueError: if `length` is not a positive integer.

    Example:
        >>> k = generate_key(5)
        >>> len(k.split())
        5
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    symbols = [secrets.randbelow(MODULUS) for _ in range(length)]
    return _symbols_to_text(symbols)


def key_for(plaintext: str) -> str:
    """
    Convenience: generates a fresh key sized exactly to `plaintext`.

    Equivalent to `generate_key(len(plaintext))`.

    Parameters:
        plaintext (str): the message the key will be used for.

    Returns:
        str: a key hex-token string with exactly len(plaintext) symbols.

    Example:
        >>> k = key_for("hello")
        >>> len(k.split())
        5
    """
    return generate_key(len(plaintext))


def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts `plaintext` with a one-time pad and returns the ciphertext
    as a printable hex-token string.

    Per-symbol operation (classic Vernam, expressed additively so that
    arbitrary Unicode text maps cleanly onto the key space):

        C_i = (P_i + K_i) mod MODULUS

    where P_i is the Unicode code point of the i-th plaintext character.

    Parameters:
        plaintext (str): the message (any Unicode text).
        key       (str): key hex-token string with at least
                          len(plaintext) symbols.

    Returns:
        str: ciphertext as space-separated hex tokens.

    Raises:
        TypeError:  if arguments are not strings.
        ValueError: if the key is shorter than the message, or if the
                    key string is malformed.

    Example:
        >>> k = key_for("hi")
        >>> c = encrypt("hi", k)
        >>> decrypt(c, k)
        'hi'
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a str")
    if not isinstance(key, str):
        raise TypeError("key must be a str (hex-token string)")

    key_symbols = _key_symbols(key)
    if len(key_symbols) < len(plaintext):
        raise ValueError(
            f"Key too short: {len(key_symbols)} < message length {len(plaintext)}"
        )

    ct_symbols = [
        (ord(ch) + k) % MODULUS
        for ch, k in zip(plaintext, key_symbols)
    ]
    return _symbols_to_text(ct_symbols)


def decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypts a one-time-pad ciphertext back into the original plaintext.

        P_i = (C_i - K_i) mod MODULUS

    Parameters:
        ciphertext (str): ciphertext hex-token string produced by `encrypt`.
        key        (str): the SAME key string used for encryption.

    Returns:
        str: recovered plaintext.

    Raises:
        TypeError:  if arguments are not strings.
        ValueError: if the key is shorter than the ciphertext, or if
                    either string is malformed.

    Example:
        >>> k = key_for("hi")
        >>> decrypt(encrypt("hi", k), k)
        'hi'
    """
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a str (hex-token string)")
    if not isinstance(key, str):
        raise TypeError("key must be a str (hex-token string)")

    ct_symbols = _text_to_symbols(ciphertext)
    key_symbols = _key_symbols(key)

    if len(key_symbols) < len(ct_symbols):
        raise ValueError(
            f"Key too short: {len(key_symbols)} < ciphertext length {len(ct_symbols)}"
        )

    plaintext = "".join(
        chr((c - k) % MODULUS)
        for c, k in zip(ct_symbols, key_symbols)
    )
    return plaintext


def symbols_to_text(symbols: list[int]) -> str:
    """
    Public wrapper: converts a list of integer symbols into a
    space-separated hex-token string. Useful if a caller wants to build
    ciphertexts manually or inspect intermediate values.

    Parameters:
        symbols (list[int]): values in [0, MODULUS).

    Returns:
        str: hex-token string.
    """
    return _symbols_to_text(symbols)


def text_to_symbols(text: str) -> list[int]:
    """
    Public wrapper: parses a hex-token string back into integer symbols.

    Parameters:
        text (str): hex-token string.

    Returns:
        list[int]: parsed symbols.
    """
    return _text_to_symbols(text)


def describe_key(key: str) -> dict:
    """
    Returns metadata about a key string without revealing the symbols.

    Useful for sanity checks and logging (e.g. "did the user paste a
    key long enough for my message?").

    Parameters:
        key (str): key hex-token string.

    Returns:
        dict with keys:
            "length"       (int)  : number of symbols
            "hex_chars"    (int)  : total hex characters (excluding spaces)
            "valid"        (bool) : True if the string parsed successfully
            "error"        (str|None): error message if not valid

    Example:
        >>> describe_key(generate_key(5))["length"]
        5
    """
    if not isinstance(key, str):
        return {"length": 0, "hex_chars": 0, "valid": False,
                "error": "key is not a str"}
    tokens = key.split()
    try:
        parsed = _text_to_symbols(key)
        return {
            "length": len(parsed),
            "hex_chars": sum(len(t) for t in tokens),
            "valid": True,
            "error": None,
        }
    except ValueError as exc:
        return {
            "length": len(tokens),
            "hex_chars": sum(len(t) for t in tokens),
            "valid": False,
            "error": str(exc),
        }