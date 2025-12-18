"""
Cipher utilities for classical encryption/decryption.
Includes Caesar, Hill, Vigenere, Vernam, Playfair, Route, Affine, Rail Fence, Columnar.
"""

import numpy as np
import re

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

