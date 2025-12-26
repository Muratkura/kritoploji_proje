"""
Cipher utilities for classical encryption/decryption.
Includes Caesar, Hill, Vigenere, Vernam, Playfair, Route, Affine, Rail Fence, Columnar.
Also includes AES and DES with both library and manual implementations.
"""

import numpy as np
import re
import base64
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding as asym_padding
    from cryptography.hazmat.primitives import serialization, hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _clean_key_letters(key: str) -> str:
    key = re.sub(r"[^A-Za-z]", "", key or "").upper()
    if not key:
        raise ValueError("Key must contain at least one letter")
    return key


def _egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, y, x = _egcd(b % a, a)
    return g, x - (b // a) * y, y


def _modinv(a: int, m: int) -> int:
    a %= m
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for a={a} mod {m}. gcd(a,m)={g}")
    return x % m


def vernam_encrypt(text, key):
    """
    Encrypt text using Vernam cipher (OTP-style on letters).
    Non-letters are preserved; key advances only on letters.
    If key is shorter than the number of letters, it repeats (like Vigenere).
    """
    key = _clean_key_letters(key)
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            ascii_offset = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            v = (ord(ch) - ascii_offset + k) % 26
            result.append(chr(v + ascii_offset))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def vernam_decrypt(text, key):
    """Decrypt Vernam cipher output (same key rules as encrypt)."""
    key = _clean_key_letters(key)
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            ascii_offset = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            v = (ord(ch) - ascii_offset - k) % 26
            result.append(chr(v + ascii_offset))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def affine_encrypt(text, key):
    """
    Encrypt text using Affine cipher.
    Key format: "a,b" where gcd(a,26)=1.
    Non-letters are preserved.
    """
    if key is None:
        raise ValueError("Key cannot be empty for Affine cipher")
    parts = [p.strip() for p in str(key).split(',')]
    if len(parts) != 2:
        raise ValueError("Affine key format must be 'a,b' (e.g. 5,8)")
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        raise ValueError("Affine key 'a,b' must be integers")

    # Validate invertibility of a
    _ = _modinv(a, 26)

    out = []
    for ch in text:
        if ch.isalpha():
            ascii_offset = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - ascii_offset
            y = (a * x + b) % 26
            out.append(chr(y + ascii_offset))
        else:
            out.append(ch)
    return ''.join(out)


def affine_decrypt(text, key):
    """
    Decrypt Affine cipher.
    Key format: "a,b" where gcd(a,26)=1.
    """
    if key is None:
        raise ValueError("Key cannot be empty for Affine cipher")
    parts = [p.strip() for p in str(key).split(',')]
    if len(parts) != 2:
        raise ValueError("Affine key format must be 'a,b' (e.g. 5,8)")
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        raise ValueError("Affine key 'a,b' must be integers")

    a_inv = _modinv(a, 26)
    out = []
    for ch in text:
        if ch.isalpha():
            ascii_offset = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - ascii_offset
            x = (a_inv * (y - b)) % 26
            out.append(chr(x + ascii_offset))
        else:
            out.append(ch)
    return ''.join(out)


def rail_fence_encrypt(text, rails):
    """
    Encrypt text using Rail Fence cipher.
    Keeps all characters (including spaces); rails must be >= 2.
    """
    try:
        rails = int(rails)
    except ValueError:
        raise ValueError("Rails must be an integer")
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    if not text:
        return ""

    fence = [[] for _ in range(rails)]
    row = 0
    direction = 1
    for ch in text:
        fence[row].append(ch)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return ''.join(''.join(r) for r in fence)


def rail_fence_decrypt(ciphertext, rails):
    """
    Decrypt Rail Fence cipher.
    """
    try:
        rails = int(rails)
    except ValueError:
        raise ValueError("Rails must be an integer")
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    n = len(ciphertext)
    if n == 0:
        return ""

    # Determine zig-zag pattern positions
    pattern = []
    row = 0
    direction = 1
    for _ in range(n):
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    # Count how many chars per rail
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1

    # Slice ciphertext into rails
    rails_data = []
    idx = 0
    for c in counts:
        rails_data.append(list(ciphertext[idx:idx + c]))
        idx += c

    # Reconstruct plaintext following pattern
    pointers = [0] * rails
    out = []
    for r in pattern:
        out.append(rails_data[r][pointers[r]])
        pointers[r] += 1
    return ''.join(out)


def columnar_encrypt(text, key):
    """
    Encrypt text using Columnar Transposition.
    Key: keyword (letters/numbers). Columns are ordered by sorted key chars (stable).
    Pads with 'X' to fill the grid.
    """
    key = str(key or "").strip()
    if not key:
        raise ValueError("Key cannot be empty for Columnar cipher")
    cols = len(key)
    if cols < 2:
        raise ValueError("Key must be at least 2 characters for Columnar cipher")

    n = len(text)
    rows = (n + cols - 1) // cols
    padded = text + ('X' * (rows * cols - n))

    grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]
    order = sorted(range(cols), key=lambda i: (key[i], i))

    out = []
    for c in order:
        for r in range(rows):
            out.append(grid[r][c])
    return ''.join(out)


def columnar_decrypt(ciphertext, key):
    """
    Decrypt Columnar Transposition.
    Expects the same key used for encryption; output includes padding 'X' if present.
    """
    key = str(key or "").strip()
    if not key:
        raise ValueError("Key cannot be empty for Columnar cipher")
    cols = len(key)
    if cols < 2:
        raise ValueError("Key must be at least 2 characters for Columnar cipher")
    n = len(ciphertext)
    rows = (n + cols - 1) // cols
    if rows * cols != n:
        raise ValueError("Ciphertext length must be a multiple of key length for Columnar decrypt")

    order = sorted(range(cols), key=lambda i: (key[i], i))
    grid = [[''] * cols for _ in range(rows)]

    idx = 0
    for c in order:
        for r in range(rows):
            grid[r][c] = ciphertext[idx]
            idx += 1

    return ''.join(''.join(row) for row in grid)


def _playfair_build_square(key: str):
    key = _clean_key_letters(key).replace('J', 'I')
    seen = set()
    square = []
    for ch in key + _ALPHABET:
        ch = 'I' if ch == 'J' else ch
        if ch == 'J':
            continue
        if ch not in seen and ch != 'J':
            seen.add(ch)
            if ch != 'J':
                square.append(ch)
    square = [c for c in square if c != 'J']
    alpha_25 = [c for c in _ALPHABET if c != 'J']
    for c in alpha_25:
        if c not in seen:
            seen.add(c)
            square.append(c)
    square = square[:25]
    pos = {square[i]: (i // 5, i % 5) for i in range(25)}
    return square, pos


def _playfair_prepare_text(text: str):
    letters = re.sub(r"[^A-Za-z]", "", text).upper().replace('J', 'I')
    pairs = []
    i = 0
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else None
        if b is None:
            pairs.append((a, 'X'))
            i += 1
        elif a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair_encrypt(text, key):
    square, pos = _playfair_build_square(key)
    pairs = _playfair_prepare_text(text)
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(square[ra * 5 + (ca + 1) % 5])
            out.append(square[rb * 5 + (cb + 1) % 5])
        elif ca == cb:
            out.append(square[((ra + 1) % 5) * 5 + ca])
            out.append(square[((rb + 1) % 5) * 5 + cb])
        else:
            out.append(square[ra * 5 + cb])
            out.append(square[rb * 5 + ca])
    return ''.join(out)


def playfair_decrypt(text, key):
    square, pos = _playfair_build_square(key)
    letters = re.sub(r"[^A-Za-z]", "", text).upper().replace('J', 'I')
    if len(letters) % 2 != 0:
        raise ValueError("Playfair ciphertext length must be even (letters only)")
    out = []
    for i in range(0, len(letters), 2):
        a, b = letters[i], letters[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(square[ra * 5 + (ca - 1) % 5])
            out.append(square[rb * 5 + (cb - 1) % 5])
        elif ca == cb:
            out.append(square[((ra - 1) % 5) * 5 + ca])
            out.append(square[((rb - 1) % 5) * 5 + cb])
        else:
            out.append(square[ra * 5 + cb])
            out.append(square[rb * 5 + ca])
    return ''.join(out)


def route_encrypt(text, key):
    try:
        cols = int(str(key).strip())
    except Exception:
        raise ValueError("Route key must be an integer column count (e.g. 5)")
    if cols < 2:
        raise ValueError("Route columns must be >= 2")
    if not text:
        return ""

    n = len(text)
    rows = (n + cols - 1) // cols
    padded = text + ('X' * (rows * cols - n))
    grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]

    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    out = []
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            out.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            out.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                out.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                out.append(grid[r][left])
            left += 1
    return ''.join(out)


def route_decrypt(ciphertext, key):
    try:
        cols = int(str(key).strip())
    except Exception:
        raise ValueError("Route key must be an integer column count (e.g. 5)")
    if cols < 2:
        raise ValueError("Route columns must be >= 2")
    n = len(ciphertext)
    if n == 0:
        return ""
    rows = (n + cols - 1) // cols
    if rows * cols != n:
        raise ValueError("Ciphertext length must be a multiple of columns for Route decrypt")

    grid = [[''] * cols for _ in range(rows)]
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    idx = 0
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            grid[top][c] = ciphertext[idx]
            idx += 1
        top += 1
        for r in range(top, bottom + 1):
            grid[r][right] = ciphertext[idx]
            idx += 1
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                grid[bottom][c] = ciphertext[idx]
                idx += 1
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                grid[r][left] = ciphertext[idx]
                idx += 1
            left += 1

    return ''.join(''.join(row) for row in grid)


def caesar_encrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def hill_encrypt(text, key_matrix):
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(text) == 0:
        return ""
    n = key_matrix.shape[0]
    while len(text) % n != 0:
        text += 'X'
    result = []
    for i in range(0, len(text), n):
        block = [ord(c) - ord('A') for c in text[i:i + n]]
        block_vector = np.array(block).reshape(n, 1)
        encrypted_vector = np.dot(key_matrix, block_vector) % 26
        encrypted_block = ''.join([chr(int(x) + ord('A')) for x in encrypted_vector.flatten()])
        result.append(encrypted_block)
    return ''.join(result)


def hill_decrypt(text, key_matrix):
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(text) == 0:
        return ""
    n = key_matrix.shape[0]
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    if det < 0:
        det = (det + 26) % 26
    det_inv = None
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break
    if det_inv is None:
        raise ValueError("Key matrix is not invertible modulo 26")
    if n == 2:
        adj = np.array([
            [key_matrix[1, 1], -key_matrix[0, 1]],
            [-key_matrix[1, 0], key_matrix[0, 0]]
        ])
    else:
        cofactors = np.zeros((3, 3), dtype=int)
        for i in range(3):
            for j in range(3):
                minor = np.delete(np.delete(key_matrix, i, axis=0), j, axis=1)
                cofactor = ((-1) ** (i + j)) * int(np.round(np.linalg.det(minor)))
                cofactors[i, j] = cofactor % 26
        adj = cofactors.T
    adj = adj % 26
    key_inv = (det_inv * adj) % 26
    result = []
    for i in range(0, len(text), n):
        block = [ord(c) - ord('A') for c in text[i:i + n]]
        block_vector = np.array(block).reshape(n, 1)
        decrypted_vector = np.dot(key_inv, block_vector) % 26
        decrypted_block = ''.join([chr(int(x) + ord('A')) for x in decrypted_vector.flatten()])
        result.append(decrypted_block)
    return ''.join(result)


def vigenere_encrypt(text, key):
    key = re.sub(r'[^A-Za-z]', '', key).upper()
    if len(key) == 0:
        raise ValueError("Key must contain at least one letter")
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            shifted = (ord(char) - ascii_offset + key_shift) % 26
            result.append(chr(shifted + ascii_offset))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(text, key):
    key = re.sub(r'[^A-Za-z]', '', key).upper()
    if len(key) == 0:
        raise ValueError("Key must contain at least one letter")
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            shifted = (ord(char) - ascii_offset - key_shift) % 26
            result.append(chr(shifted + ascii_offset))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)


# ==================== AES Implementation ====================

def aes_encrypt_library(text, key):
    """
    AES encryption using cryptography library.
    Key: string (will be padded/truncated to 16, 24, or 32 bytes)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for AES library implementation")
    
    if not key:
        raise ValueError("Key cannot be empty for AES")
    
    # Convert key to bytes and ensure proper length (16, 24, or 32 bytes)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) < 24:
        key_bytes = key_bytes.ljust(24, b'\0')
    elif len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')
    else:
        key_bytes = key_bytes[:32]
    
    # Use AES-128, AES-192, or AES-256 based on key length
    if len(key_bytes) == 16:
        algorithm = algorithms.AES(key_bytes)
    elif len(key_bytes) == 24:
        algorithm = algorithms.AES(key_bytes)
    else:
        algorithm = algorithms.AES(key_bytes)
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text_bytes) + padder.finalize()
    
    # Generate IV (Initialization Vector)
    import os
    iv = os.urandom(16)
    
    # Encrypt
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and ciphertext, then encode to base64
    result = base64.b64encode(iv + ciphertext).decode('utf-8')
    return result


def aes_decrypt_library(ciphertext, key):
    """
    AES decryption using cryptography library.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for AES library implementation")
    
    if not key:
        raise ValueError("Key cannot be empty for AES")
    
    # Convert key to bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) < 24:
        key_bytes = key_bytes.ljust(24, b'\0')
    elif len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')
    else:
        key_bytes = key_bytes[:32]
    
    # Decode base64
    try:
        data = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid base64 ciphertext")
    
    # Extract IV and ciphertext
    iv = data[:16]
    encrypted_data = data[16:]
    
    # Decrypt
    algorithm = algorithms.AES(key_bytes)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


# AES S-box
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# AES Inverse S-box
_AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Rcon for AES key expansion
_AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _aes_sub_bytes(state):
    """SubBytes transformation"""
    return [[_AES_SBOX[b] for b in row] for row in state]


def _aes_inv_sub_bytes(state):
    """Inverse SubBytes transformation"""
    return [[_AES_INV_SBOX[b] for b in row] for row in state]


def _aes_shift_rows(state):
    """ShiftRows transformation"""
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]]
    ]


def _aes_inv_shift_rows(state):
    """Inverse ShiftRows transformation"""
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][3], state[1][0], state[1][1], state[1][2]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][1], state[3][2], state[3][3], state[3][0]]
    ]


def _aes_gmul(a, b):
    """Galois Field multiplication"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xff


def _aes_mix_columns(state):
    """MixColumns transformation"""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        new_state[0][c] = _aes_gmul(0x02, state[0][c]) ^ _aes_gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
        new_state[1][c] = state[0][c] ^ _aes_gmul(0x02, state[1][c]) ^ _aes_gmul(0x03, state[2][c]) ^ state[3][c]
        new_state[2][c] = state[0][c] ^ state[1][c] ^ _aes_gmul(0x02, state[2][c]) ^ _aes_gmul(0x03, state[3][c])
        new_state[3][c] = _aes_gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ _aes_gmul(0x02, state[3][c])
    return new_state


def _aes_inv_mix_columns(state):
    """Inverse MixColumns transformation"""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        new_state[0][c] = _aes_gmul(0x0e, state[0][c]) ^ _aes_gmul(0x0b, state[1][c]) ^ _aes_gmul(0x0d, state[2][c]) ^ _aes_gmul(0x09, state[3][c])
        new_state[1][c] = _aes_gmul(0x09, state[0][c]) ^ _aes_gmul(0x0e, state[1][c]) ^ _aes_gmul(0x0b, state[2][c]) ^ _aes_gmul(0x0d, state[3][c])
        new_state[2][c] = _aes_gmul(0x0d, state[0][c]) ^ _aes_gmul(0x09, state[1][c]) ^ _aes_gmul(0x0e, state[2][c]) ^ _aes_gmul(0x0b, state[3][c])
        new_state[3][c] = _aes_gmul(0x0b, state[0][c]) ^ _aes_gmul(0x0d, state[1][c]) ^ _aes_gmul(0x09, state[2][c]) ^ _aes_gmul(0x0e, state[3][c])
    return new_state


def _aes_add_round_key(state, round_key):
    """AddRoundKey transformation"""
    return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]


def _aes_key_expansion(key_bytes):
    """Key expansion for AES-128"""
    Nk = len(key_bytes) // 4  # Number of 32-bit words in key
    Nr = 10 if Nk == 4 else 12 if Nk == 6 else 14  # Number of rounds
    
    # Initialize key schedule
    w = []
    for i in range(Nk):
        w.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])
    
    # Expand key
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            # RotWord
            temp = [temp[1], temp[2], temp[3], temp[0]]
            # SubWord
            temp = [_AES_SBOX[b] for b in temp]
            # XOR with Rcon
            temp[0] ^= _AES_RCON[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            # SubWord
            temp = [_AES_SBOX[b] for b in temp]
        
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    
    # Convert to round keys
    round_keys = []
    for i in range(Nr + 1):
        round_key = [[0] * 4 for _ in range(4)]
        for j in range(4):
            for k in range(4):
                round_key[k][j] = w[i*4 + j][k]
        round_keys.append(round_key)
    
    return round_keys, Nr


def aes_encrypt_manual(text, key):
    """
    AES encryption without library (manual implementation).
    Simplified AES-128 implementation.
    Key: string (will be padded/truncated to 16 bytes)
    Returns hex encoded ciphertext.
    """
    if not key:
        raise ValueError("Key cannot be empty for AES")
    
    # Prepare key (16 bytes for AES-128)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    else:
        key_bytes = key_bytes[:16]
    
    # Prepare text (pad to multiple of 16 bytes)
    text_bytes = text.encode('utf-8')
    padding_len = 16 - (len(text_bytes) % 16)
    text_bytes = text_bytes + bytes([padding_len] * padding_len)
    
    # Expand key
    round_keys, Nr = _aes_key_expansion(list(key_bytes))
    
    # Encrypt each block
    ciphertext = []
    for block_start in range(0, len(text_bytes), 16):
        block = text_bytes[block_start:block_start+16]
        
        # Convert block to state matrix
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = block[i*4 + j]
        
        # Initial round key addition
        state = _aes_add_round_key(state, round_keys[0])
        
        # Main rounds
        for round_num in range(1, Nr):
            state = _aes_sub_bytes(state)
            state = _aes_shift_rows(state)
            state = _aes_mix_columns(state)
            state = _aes_add_round_key(state, round_keys[round_num])
        
        # Final round (no MixColumns)
        state = _aes_sub_bytes(state)
        state = _aes_shift_rows(state)
        state = _aes_add_round_key(state, round_keys[Nr])
        
        # Convert state back to bytes
        for i in range(4):
            for j in range(4):
                ciphertext.append(state[j][i])
    
    return ''.join(f'{b:02x}' for b in ciphertext)


def aes_decrypt_manual(ciphertext, key):
    """
    AES decryption without library (manual implementation).
    """
    if not key:
        raise ValueError("Key cannot be empty for AES")
    
    # Prepare key
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\0')
    else:
        key_bytes = key_bytes[:16]
    
    # Decode hex
    try:
        cipher_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        raise ValueError("Invalid hex ciphertext")
    
    if len(cipher_bytes) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16 bytes")
    
    # Expand key
    round_keys, Nr = _aes_key_expansion(list(key_bytes))
    
    # Decrypt each block
    plaintext = []
    for block_start in range(0, len(cipher_bytes), 16):
        block = cipher_bytes[block_start:block_start+16]
        
        # Convert block to state matrix
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = block[i*4 + j]
        
        # Initial round key addition
        state = _aes_add_round_key(state, round_keys[Nr])
        
        # Main rounds
        for round_num in range(Nr - 1, 0, -1):
            state = _aes_inv_shift_rows(state)
            state = _aes_inv_sub_bytes(state)
            state = _aes_add_round_key(state, round_keys[round_num])
            state = _aes_inv_mix_columns(state)
        
        # Final round (no MixColumns)
        state = _aes_inv_shift_rows(state)
        state = _aes_inv_sub_bytes(state)
        state = _aes_add_round_key(state, round_keys[0])
        
        # Convert state back to bytes
        for i in range(4):
            for j in range(4):
                plaintext.append(state[j][i])
    
    # Remove padding
    if plaintext:
        padding_len = plaintext[-1]
        if padding_len > 0 and padding_len <= 16:
            plaintext = plaintext[:-padding_len]
    
    return bytes(plaintext).decode('utf-8', errors='ignore')


# ==================== DES Implementation ====================

def des_encrypt_library(text, key):
    """
    DES encryption using cryptography library.
    Key: string (will be padded/truncated to 8 bytes)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DES library implementation")
    
    if not key:
        raise ValueError("Key cannot be empty for DES")
    
    # Convert key to bytes (8 bytes for DES)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'\0')
    else:
        key_bytes = key_bytes[:8]
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # Pad the data
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text_bytes) + padder.finalize()
    
    # Generate IV
    import os
    iv = os.urandom(8)
    
    # Encrypt
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and ciphertext, then encode to base64
    result = base64.b64encode(iv + ciphertext).decode('utf-8')
    return result


def des_decrypt_library(ciphertext, key):
    """
    DES decryption using cryptography library.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DES library implementation")
    
    if not key:
        raise ValueError("Key cannot be empty for DES")
    
    # Convert key to bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'\0')
    else:
        key_bytes = key_bytes[:8]
    
    # Decode base64
    try:
        data = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid base64 ciphertext")
    
    # Extract IV and ciphertext
    iv = data[:8]
    encrypted_data = data[8:]
    
    # Decrypt
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


# DES Permutation tables
_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
]

_DES_IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
]

_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
]

_DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

_DES_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
]

_DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

_DES_S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _des_permute(block, table):
    """Apply permutation table to block"""
    return [block[i - 1] for i in table]


def _des_key_schedule(key_bits):
    """Generate 16 round keys"""
    # PC1 permutation
    key_56 = _des_permute(key_bits, _DES_PC1)
    
    # Split into C0 and D0
    C = key_56[:28]
    D = key_56[28:]
    
    round_keys = []
    for round_num in range(16):
        # Left shift
        shift = _DES_SHIFTS[round_num]
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        
        # Combine and apply PC2
        CD = C + D
        round_key = _des_permute(CD, _DES_PC2)
        round_keys.append(round_key)
    
    return round_keys


def _des_f_function(R, round_key):
    """Feistel function"""
    # Expand R from 32 to 48 bits
    E_R = _des_permute(R, _DES_E)
    
    # XOR with round key
    xor_result = [E_R[i] ^ round_key[i] for i in range(48)]
    
    # S-box substitution
    S_output = []
    for i in range(8):
        block = xor_result[i*6:(i+1)*6]
        row = block[0] * 2 + block[5]
        col = block[1] * 8 + block[2] * 4 + block[3] * 2 + block[4]
        s_value = _DES_S_BOXES[i][row][col]
        S_output.extend([(s_value >> j) & 1 for j in range(3, -1, -1)])
    
    # P permutation
    return _des_permute(S_output, _DES_P)


def des_encrypt_manual(text, key):
    """
    DES encryption without library (manual implementation).
    Key: string (will be padded/truncated to 8 bytes)
    Returns hex encoded ciphertext.
    """
    if not key:
        raise ValueError("Key cannot be empty for DES")
    
    # Prepare key (8 bytes for DES)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'\0')
    else:
        key_bytes = key_bytes[:8]
    
    # Convert key to bits
    key_bits = []
    for byte in key_bytes:
        key_bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
    
    # Generate round keys
    round_keys = _des_key_schedule(key_bits)
    
    # Prepare text (pad to multiple of 8 bytes)
    text_bytes = text.encode('utf-8')
    padding_len = 8 - (len(text_bytes) % 8)
    text_bytes = text_bytes + bytes([padding_len] * padding_len)
    
    # Encrypt each block
    ciphertext = []
    for block_start in range(0, len(text_bytes), 8):
        block = text_bytes[block_start:block_start+8]
        
        # Convert block to bits
        block_bits = []
        for byte in block:
            block_bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        
        # Initial permutation
        block_bits = _des_permute(block_bits, _DES_IP)
        
        # Split into L0 and R0
        L = block_bits[:32]
        R = block_bits[32:]
        
        # 16 rounds
        for round_num in range(16):
            L_new = R
            R_new = [L[i] ^ _des_f_function(R, round_keys[round_num])[i] for i in range(32)]
            L = L_new
            R = R_new
        
        # Combine R16 and L16 (swap)
        RL = R + L
        
        # Final permutation
        cipher_bits = _des_permute(RL, _DES_IP_INV)
        
        # Convert bits back to bytes
        for i in range(0, 64, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | cipher_bits[i + j]
            ciphertext.append(byte)
    
    return ''.join(f'{b:02x}' for b in ciphertext)


def des_decrypt_manual(ciphertext, key):
    """
    DES decryption without library (manual implementation).
    """
    if not key:
        raise ValueError("Key cannot be empty for DES")
    
    # Prepare key
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'\0')
    else:
        key_bytes = key_bytes[:8]
    
    # Convert key to bits
    key_bits = []
    for byte in key_bytes:
        key_bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
    
    # Generate round keys
    round_keys = _des_key_schedule(key_bits)
    
    # Decode hex
    try:
        cipher_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        raise ValueError("Invalid hex ciphertext")
    
    if len(cipher_bytes) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8 bytes")
    
    # Decrypt each block
    plaintext = []
    for block_start in range(0, len(cipher_bytes), 8):
        block = cipher_bytes[block_start:block_start+8]
        
        # Convert block to bits
        block_bits = []
        for byte in block:
            block_bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        
        # Initial permutation
        block_bits = _des_permute(block_bits, _DES_IP)
        
        # Split into L0 and R0
        L = block_bits[:32]
        R = block_bits[32:]
        
        # 16 rounds (reverse order)
        for round_num in range(15, -1, -1):
            L_new = R
            R_new = [L[i] ^ _des_f_function(R, round_keys[round_num])[i] for i in range(32)]
            L = L_new
            R = R_new
        
        # Combine R0 and L0 (swap)
        RL = R + L
        
        # Final permutation
        plain_bits = _des_permute(RL, _DES_IP_INV)
        
        # Convert bits back to bytes
        for i in range(0, 64, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | plain_bits[i + j]
            plaintext.append(byte)
    
    # Remove padding
    if plaintext:
        padding_len = plaintext[-1]
        if padding_len > 0 and padding_len <= 8:
            plaintext = plaintext[:-padding_len]
    
    return bytes(plaintext).decode('utf-8', errors='ignore')


# ==================== RSA Implementation ====================

def rsa_generate_keypair(key_size=2048):
    """
    Generate RSA key pair.
    Returns (public_key_pem, private_key_pem) as strings.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for RSA")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem


def rsa_encrypt_library(text, public_key_pem):
    """
    RSA encryption using cryptography library.
    public_key_pem: Public key in PEM format (string)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for RSA")
    
    if not public_key_pem:
        raise ValueError("RSA için public key boş olamaz")
    
    # Clean and validate public key format
    public_key_pem = public_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PUBLIC KEY' not in public_key_pem or 'END PUBLIC KEY' not in public_key_pem:
        raise ValueError("Geçersiz public key formatı: Public key BEGIN/END PUBLIC KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load public key from PEM
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz public key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # RSA encryption with OAEP padding
    ciphertext = public_key.encrypt(
        text_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encode to base64
    return base64.b64encode(ciphertext).decode('utf-8')


def rsa_decrypt_library(ciphertext, private_key_pem):
    """
    RSA decryption using cryptography library.
    private_key_pem: Private key in PEM format (string)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for RSA")
    
    if not private_key_pem:
        raise ValueError("RSA için private key boş olamaz")
    
    # Clean and validate private key format
    private_key_pem = private_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PRIVATE KEY' not in private_key_pem or 'END PRIVATE KEY' not in private_key_pem:
        # Try alternative formats
        if 'BEGIN RSA PRIVATE KEY' not in private_key_pem or 'END RSA PRIVATE KEY' not in private_key_pem:
            raise ValueError("Geçersiz private key formatı: Private key BEGIN/END PRIVATE KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load private key from PEM
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz private key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Decode base64
    try:
        cipher_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid base64 ciphertext")
    
    # RSA decryption with OAEP padding
    try:
        plaintext = private_key.decrypt(
            cipher_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Deşifreleme başarısız: {e}")
    
    return plaintext.decode('utf-8')


def rsa_encrypt_manual(text, public_key_pem):
    """
    RSA encryption without library (simplified manual implementation).
    Note: This is a simplified version for educational purposes.
    For production use, always use the library version.
    public_key_pem: Public key in PEM format (string)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for RSA key parsing")
    
    if not public_key_pem:
        raise ValueError("RSA için public key boş olamaz")
    
    try:
        # Load public key to get n and e
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Get public key numbers
        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
    except Exception as e:
        raise ValueError(f"Geçersiz public key formatı: {e}")
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # RSA encryption: c = m^e mod n
    # For simplicity, we'll encrypt each byte separately
    # In real RSA, we'd use proper padding (OAEP/PKCS1)
    ciphertext = []
    for byte in text_bytes:
        # Encrypt: c = byte^e mod n
        c = pow(byte, e, n)
        # Convert to bytes (big-endian)
        ciphertext.extend(c.to_bytes((c.bit_length() + 7) // 8, 'big'))
    
    # Encode to base64
    return base64.b64encode(bytes(ciphertext)).decode('utf-8')


def rsa_decrypt_manual(ciphertext, private_key_pem):
    """
    RSA decryption without library (simplified manual implementation).
    Note: This is a simplified version for educational purposes.
    For production use, always use the library version.
    private_key_pem: Private key in PEM format (string)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for RSA key parsing")
    
    if not private_key_pem:
        raise ValueError("RSA için private key boş olamaz")
    
    try:
        # Load private key to get n and d
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Get private key numbers
        private_numbers = private_key.private_numbers()
        n = private_numbers.public_numbers.n
        d = private_numbers.d  # d is the private exponent
    except Exception as e:
        raise ValueError(f"Geçersiz private key formatı: {e}")
    
    # Decode base64
    try:
        cipher_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid base64 ciphertext")
    
    # RSA decryption: m = c^d mod n
    # This is a simplified version - in practice, proper padding is needed
    plaintext = []
    i = 0
    key_size_bytes = (n.bit_length() + 7) // 8
    
    while i < len(cipher_bytes):
        # Read a block
        block = cipher_bytes[i:i+key_size_bytes]
        if not block:
            break
        
        # Convert block to integer
        c = int.from_bytes(block, 'big')
        
        # Decrypt: m = c^d mod n
        try:
            m = pow(c, d, n)
            # Convert back to byte
            if m < 256:
                plaintext.append(m)
        except Exception:
            pass
        
        i += key_size_bytes
    
    return bytes(plaintext).decode('utf-8', errors='ignore')


# ==================== DSA Implementation ====================

def dsa_generate_keypair(key_size=2048):
    """
    Generate DSA key pair.
    Returns (public_key_pem, private_key_pem) as strings.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DSA")
    
    # Generate private key
    private_key = dsa.generate_private_key(
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem


def dsa_encrypt_library(text, public_key_pem):
    """
    DSA encryption using cryptography library.
    Note: DSA is primarily for signatures, but we'll use it for encryption demonstration.
    public_key_pem: Public key in PEM format (string)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DSA")
    
    if not public_key_pem:
        raise ValueError("DSA için public key boş olamaz")
    
    # Clean and validate public key format
    public_key_pem = public_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PUBLIC KEY' not in public_key_pem or 'END PUBLIC KEY' not in public_key_pem:
        raise ValueError("Geçersiz public key formatı: Public key BEGIN/END PUBLIC KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load public key from PEM
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz public key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # DSA is typically used for signatures, not encryption
    # For demonstration, we'll use a hybrid approach with symmetric encryption
    # In practice, DSA should be used with a symmetric cipher like AES
    # Here we'll use a simplified approach for educational purposes
    
    # Hash the message and use DSA-like operations
    # Note: This is a simplified implementation for demonstration
    import hashlib
    hash_obj = hashlib.sha256(text_bytes)
    message_hash = hash_obj.digest()
    
    # For encryption demonstration, we'll encode the hash
    # In real DSA, this would be used for signing
    ciphertext = base64.b64encode(message_hash + text_bytes).decode('utf-8')
    
    return ciphertext


def dsa_decrypt_library(ciphertext, private_key_pem):
    """
    DSA decryption using cryptography library.
    Note: DSA is primarily for signatures, this is a simplified decryption.
    private_key_pem: Private key in PEM format (string)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DSA")
    
    if not private_key_pem:
        raise ValueError("DSA için private key boş olamaz")
    
    # Clean and validate private key format
    private_key_pem = private_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PRIVATE KEY' not in private_key_pem or 'END PRIVATE KEY' not in private_key_pem:
        raise ValueError("Geçersiz private key formatı: Private key BEGIN/END PRIVATE KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load private key from PEM
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz private key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Decode base64
    try:
        cipher_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Geçersiz base64 şifreli metin")
    
    # Extract message (skip hash part)
    # In our simplified implementation, hash is 32 bytes (SHA256)
    if len(cipher_bytes) < 32:
        raise ValueError("Geçersiz şifreli metin formatı")
    
    plaintext = cipher_bytes[32:].decode('utf-8')
    
    return plaintext


def dsa_encrypt_manual(text, public_key_pem):
    """
    DSA encryption without library (simplified manual implementation).
    Note: This is a simplified version for educational purposes.
    For production use, always use the library version.
    public_key_pem: Public key in PEM format (string)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DSA key parsing")
    
    if not public_key_pem:
        raise ValueError("DSA için public key boş olamaz")
    
    try:
        # Load public key to get parameters
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Get public key numbers
        public_numbers = public_key.public_numbers()
        # DSA has p, q, g, y parameters
        p = public_numbers.parameter_numbers.p
        q = public_numbers.parameter_numbers.q
        g = public_numbers.parameter_numbers.g
        y = public_numbers.y
    except Exception as e:
        raise ValueError(f"Geçersiz public key formatı: {e}")
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # Simplified DSA-like encryption for demonstration
    # In real DSA, this would be used for signing
    ciphertext = []
    for byte in text_bytes:
        # Simple transformation using DSA parameters
        c = pow(byte, g, p) % q
        ciphertext.extend(c.to_bytes((c.bit_length() + 7) // 8, 'big'))
    
    # Encode to base64
    return base64.b64encode(bytes(ciphertext)).decode('utf-8')


def dsa_decrypt_manual(ciphertext, private_key_pem):
    """
    DSA decryption without library (simplified manual implementation).
    Note: This is a simplified version for educational purposes.
    For production use, always use the library version.
    private_key_pem: Private key in PEM format (string)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for DSA key parsing")
    
    if not private_key_pem:
        raise ValueError("DSA için private key boş olamaz")
    
    try:
        # Load private key to get parameters
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Get private key numbers
        private_numbers = private_key.private_numbers()
        # DSA has p, q, g, x parameters
        p = private_numbers.public_numbers.parameter_numbers.p
        q = private_numbers.public_numbers.parameter_numbers.q
        g = private_numbers.public_numbers.parameter_numbers.g
        x = private_numbers.x  # private exponent
    except Exception as e:
        raise ValueError(f"Geçersiz private key formatı: {e}")
    
    # Decode base64
    try:
        cipher_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Geçersiz base64 şifreli metin")
    
    # Simplified DSA-like decryption
    plaintext = []
    i = 0
    while i < len(cipher_bytes):
        # Read a block (simplified)
        block_size = min(8, len(cipher_bytes) - i)
        block = cipher_bytes[i:i+block_size]
        if not block:
            break
        
        # Convert block to integer
        c = int.from_bytes(block, 'big')
        
        # Simplified decryption
        try:
            # This is a very simplified version for demonstration
            m = pow(c, x, p) % 256
            if m < 256:
                plaintext.append(m)
        except Exception:
            pass
        
        i += block_size
    
    return bytes(plaintext).decode('utf-8', errors='ignore')


# ==================== ECC Implementation ====================

def ecc_generate_keypair(curve_name='secp256r1'):
    """
    Generate ECC key pair.
    curve_name: 'secp192r1', 'secp224r1', 'secp256r1', 'secp384r1', 'secp521r1'
    Returns (public_key_pem, private_key_pem) as strings.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for ECC")
    
    # Map curve names to EC curve objects
    curve_map = {
        'secp192r1': ec.SECP192R1(),
        'secp224r1': ec.SECP224R1(),
        'secp256r1': ec.SECP256R1(),
        'secp384r1': ec.SECP384R1(),
        'secp521r1': ec.SECP521R1(),
    }
    
    if curve_name not in curve_map:
        raise ValueError(f"Geçersiz eğri adı: {curve_name}. Desteklenen: {', '.join(curve_map.keys())}")
    
    # Generate private key
    private_key = ec.generate_private_key(
        curve_map[curve_name],
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem


def ecc_encrypt_library(text, public_key_pem):
    """
    ECC encryption using cryptography library.
    Note: ECC is typically used for key exchange and signatures, 
    but we'll use it with ECDH for encryption demonstration.
    public_key_pem: Public key in PEM format (string)
    Returns base64 encoded ciphertext.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for ECC")
    
    if not public_key_pem:
        raise ValueError("ECC için public key boş olamaz")
    
    # Clean and validate public key format
    public_key_pem = public_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PUBLIC KEY' not in public_key_pem or 'END PUBLIC KEY' not in public_key_pem:
        raise ValueError("Geçersiz public key formatı: Public key BEGIN/END PUBLIC KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load public key from PEM
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz public key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Convert text to bytes
    text_bytes = text.encode('utf-8')
    
    # ECC encryption using ECDH (Elliptic Curve Diffie-Hellman)
    # Generate ephemeral key pair for this encryption
    ephemeral_private = ec.generate_private_key(
        public_key.curve,
        backend=default_backend()
    )
    ephemeral_public = ephemeral_private.public_key()
    
    # Perform ECDH key exchange
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
    
    # Derive encryption key from shared secret
    import hashlib
    derived_key = hashlib.sha256(shared_key).digest()
    
    # Use AES for actual encryption (hybrid encryption)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    
    # Encrypt the message
    ciphertext = aesgcm.encrypt(nonce, text_bytes, None)
    
    # Combine ephemeral public key, nonce, and ciphertext
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Encode to base64
    combined = base64.b64encode(ephemeral_public_bytes + b'|||' + nonce + b'|||' + ciphertext).decode('utf-8')
    
    return combined


def ecc_decrypt_library(ciphertext, private_key_pem):
    """
    ECC decryption using cryptography library.
    private_key_pem: Private key in PEM format (string)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError("cryptography library is required for ECC")
    
    if not private_key_pem:
        raise ValueError("ECC için private key boş olamaz")
    
    # Clean and validate private key format
    private_key_pem = private_key_pem.strip()
    
    # Check for proper PEM delimiters
    if 'BEGIN PRIVATE KEY' not in private_key_pem or 'END PRIVATE KEY' not in private_key_pem:
        raise ValueError("Geçersiz private key formatı: Private key BEGIN/END PRIVATE KEY sınırlayıcılarını içermelidir. Lütfen tüm satırları dahil olmak üzere anahtarın tamamını kopyaladığınızdan emin olun.")
    
    try:
        # Load private key from PEM
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Geçersiz private key formatı: {str(e)}. Lütfen anahtarın PEM formatında olduğundan ve BEGIN/END sınırlayıcılarını içerdiğinden emin olun.")
    
    # Decode base64
    try:
        combined_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    except Exception:
        raise ValueError("Geçersiz base64 şifreli metin")
    
    # Split ephemeral public key, nonce, and ciphertext
    parts = combined_bytes.split(b'|||')
    if len(parts) != 3:
        raise ValueError("Geçersiz şifreli metin formatı")
    
    ephemeral_public_bytes, nonce, encrypted_data = parts
    
    # Load ephemeral public key
    try:
        ephemeral_public = serialization.load_pem_public_key(
            ephemeral_public_bytes,
            backend=default_backend()
        )
    except Exception:
        raise ValueError("Geçersiz ephemeral public key formatı")
    
    # Perform ECDH key exchange
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
    
    # Derive decryption key from shared secret
    import hashlib
    derived_key = hashlib.sha256(shared_key).digest()
    
    # Use AES for actual decryption
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(derived_key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise ValueError(f"Deşifreleme başarısız: {e}")
    
    return plaintext.decode('utf-8')

