"""
Cipher utilities for Caesar, Hill, and Vigenere encryption/decryption
"""

import numpy as np
import re


def caesar_encrypt(text, shift):
    """
    Encrypt text using Caesar cipher
    
    Args:
        text: Plain text to encrypt
        shift: Shift value (integer)
    
    Returns:
        Encrypted text
    """
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
    """
    Decrypt text using Caesar cipher
    
    Args:
        text: Encrypted text
        shift: Shift value (integer)
    
    Returns:
        Decrypted text
    """
    return caesar_encrypt(text, -shift)


def hill_encrypt(text, key_matrix):
    """
    Encrypt text using Hill cipher
    
    Args:
        text: Plain text to encrypt (only letters, will be converted to uppercase)
        key_matrix: 2x2 or 3x3 numpy array key matrix
    
    Returns:
        Encrypted text
    """
    # Remove non-alphabetic characters and convert to uppercase
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    
    if len(text) == 0:
        return ""
    
    n = key_matrix.shape[0]
    
    # Pad text if necessary
    while len(text) % n != 0:
        text += 'X'
    
    result = []
    for i in range(0, len(text), n):
        # Convert block to numbers
        block = [ord(c) - ord('A') for c in text[i:i+n]]
        block_vector = np.array(block).reshape(n, 1)
        
        # Multiply by key matrix
        encrypted_vector = np.dot(key_matrix, block_vector) % 26
        
        # Convert back to letters
        encrypted_block = ''.join([chr(int(x) + ord('A')) for x in encrypted_vector.flatten()])
        result.append(encrypted_block)
    
    return ''.join(result)


def hill_decrypt(text, key_matrix):
    """
    Decrypt text using Hill cipher
    
    Args:
        text: Encrypted text (only letters, will be converted to uppercase)
        key_matrix: 2x2 or 3x3 numpy array key matrix
    
    Returns:
        Decrypted text
    """
    # Remove non-alphabetic characters and convert to uppercase
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    
    if len(text) == 0:
        return ""
    
    n = key_matrix.shape[0]
    
    # Calculate modular inverse of key matrix
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    if det < 0:
        det = (det + 26) % 26
    
    # Find modular inverse of determinant
    det_inv = None
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break
    
    if det_inv is None:
        raise ValueError("Key matrix is not invertible modulo 26")
    
    # Calculate adjugate (adjoint) matrix
    if n == 2:
        # For 2x2: adj = [[d, -b], [-c, a]]
        adj = np.array([
            [key_matrix[1, 1], -key_matrix[0, 1]],
            [-key_matrix[1, 0], key_matrix[0, 0]]
        ])
    else:  # n == 3
        # For 3x3: calculate cofactor matrix and transpose
        cofactors = np.zeros((3, 3), dtype=int)
        for i in range(3):
            for j in range(3):
                minor = np.delete(np.delete(key_matrix, i, axis=0), j, axis=1)
                cofactor = ((-1) ** (i + j)) * int(np.round(np.linalg.det(minor)))
                cofactors[i, j] = cofactor % 26
        adj = cofactors.T
    
    # Ensure adjugate is positive modulo 26
    adj = adj % 26
    
    # Calculate inverse key matrix: key_inv = det_inv * adj (mod 26)
    key_inv = (det_inv * adj) % 26
    
    result = []
    for i in range(0, len(text), n):
        # Convert block to numbers
        block = [ord(c) - ord('A') for c in text[i:i+n]]
        block_vector = np.array(block).reshape(n, 1)
        
        # Multiply by inverse key matrix
        decrypted_vector = np.dot(key_inv, block_vector) % 26
        
        # Convert back to letters
        decrypted_block = ''.join([chr(int(x) + ord('A')) for x in decrypted_vector.flatten()])
        result.append(decrypted_block)
    
    return ''.join(result)


def vigenere_encrypt(text, key):
    """
    Encrypt text using Vigenere cipher
    
    Args:
        text: Plain text to encrypt
        key: Key string (only letters will be used)
    
    Returns:
        Encrypted text
    """
    # Remove non-alphabetic characters from key and convert to uppercase
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
    """
    Decrypt text using Vigenere cipher
    
    Args:
        text: Encrypted text
        key: Key string (only letters will be used)
    
    Returns:
        Decrypted text
    """
    # Remove non-alphabetic characters from key and convert to uppercase
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

