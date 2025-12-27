"""
Flask web server for encryption/decryption
"""

from flask import Flask, render_template, request, jsonify
import numpy as np
import json
import re
import time
from cipher_utils import (
    caesar_encrypt, caesar_decrypt,
    hill_encrypt, hill_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    vernam_encrypt, vernam_decrypt,
    playfair_encrypt, playfair_decrypt,
    route_encrypt, route_decrypt,
    affine_encrypt, affine_decrypt,
    rail_fence_encrypt, rail_fence_decrypt,
    columnar_encrypt, columnar_decrypt,
    aes_encrypt_library, aes_decrypt_library,
    aes_encrypt_manual, aes_decrypt_manual,
    des_encrypt_library, des_decrypt_library,
    des_encrypt_manual, des_decrypt_manual,
    rsa_generate_keypair, rsa_encrypt_library, rsa_decrypt_library,
    dsa_generate_keypair, dsa_encrypt_library, dsa_decrypt_library,
    ecc_generate_keypair, ecc_encrypt_library, ecc_decrypt_library
)

app = Flask(__name__)


def parse_hill_key(key_str):
    """
    Parse Hill cipher key from string format
    """
    try:
        if isinstance(key_str, str):
            key_list = json.loads(key_str)
        else:
            key_list = key_str
        key_matrix = np.array(key_list)
        if key_matrix.shape not in [(2, 2), (3, 3)]:
            raise ValueError("Key matrix must be 2x2 or 3x3")
        return key_matrix
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid key format: {e}")


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


@app.route('/api/rsa/generate-keys', methods=['POST'])
def generate_rsa_keys():
    """API endpoint for generating RSA key pair"""
    try:
        data = request.get_json() or {}
        key_size = data.get('key_size', 2048)
        
        try:
            key_size = int(key_size)
            if key_size not in [1024, 2048, 3072, 4096]:
                return jsonify({'error': 'Anahtar boyutu 1024, 2048, 3072 veya 4096 olmalıdır'}), 400
        except (ValueError, TypeError):
                return jsonify({'error': 'Geçersiz anahtar boyutu. Tam sayı olmalıdır.'}), 400
        
        try:
            public_key, private_key = rsa_generate_keypair(key_size)
            return jsonify({
                'success': True,
                'public_key': public_key,
                'private_key': private_key,
                'key_size': key_size
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    except Exception as e:
        return jsonify({'error': f'Sunucu hatası: {str(e)}'}), 500


@app.route('/api/dsa/generate-keys', methods=['POST'])
def generate_dsa_keys():
    """API endpoint for generating DSA key pair"""
    try:
        data = request.get_json() or {}
        key_size = data.get('key_size', 2048)
        
        try:
            key_size = int(key_size)
            if key_size not in [1024, 2048, 3072]:
                return jsonify({'error': 'DSA anahtar boyutu 1024, 2048 veya 3072 olmalıdır'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Geçersiz anahtar boyutu. Tam sayı olmalıdır.'}), 400
        
        try:
            public_key, private_key = dsa_generate_keypair(key_size)
            return jsonify({
                'success': True,
                'public_key': public_key,
                'private_key': private_key,
                'key_size': key_size
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    except Exception as e:
        return jsonify({'error': f'Sunucu hatası: {str(e)}'}), 500


@app.route('/api/ecc/generate-keys', methods=['POST'])
def generate_ecc_keys():
    """API endpoint for generating ECC key pair"""
    try:
        data = request.get_json() or {}
        curve_name = data.get('curve_name', 'secp256r1')
        
        try:
            public_key, private_key = ecc_generate_keypair(curve_name)
            return jsonify({
                'success': True,
                'public_key': public_key,
                'private_key': private_key,
                'curve_name': curve_name
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    except Exception as e:
        return jsonify({'error': f'Sunucu hatası: {str(e)}'}), 500


@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """API endpoint for encryption"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        cipher_type = data.get('cipher_type', '').lower()
        key = data.get('key', '')
        
        if not message:
            return jsonify({'error': 'Mesaj boş olamaz'}), 400
        
        if cipher_type == 'caesar':
            try:
                shift = int(key)
                encrypted = caesar_encrypt(message, shift)
            except ValueError:
                return jsonify({'error': 'Geçersiz kaydırma değeri. Tam sayı olmalıdır.'}), 400
        
        elif cipher_type == 'hill':
            try:
                key_matrix = parse_hill_key(key)
                encrypted = hill_encrypt(message, key_matrix)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        elif cipher_type == 'vigenere':
            if not key:
                return jsonify({'error': 'Vigenere şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = vigenere_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'vernam':
            if not key:
                return jsonify({'error': 'Vernam şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = vernam_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'playfair':
            if not key:
                return jsonify({'error': 'Playfair şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = playfair_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'route':
            if not key:
                return jsonify({'error': 'Route şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = route_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'affine':
            if not key:
                return jsonify({'error': 'Affine şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = affine_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rail_fence':
            if not key:
                return jsonify({'error': 'Rail Fence şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = rail_fence_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'columnar':
            if not key:
                return jsonify({'error': 'Columnar şifresi için anahtar boş olamaz'}), 400
            try:
                encrypted = columnar_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'aes_library':
            if not key:
                return jsonify({'error': 'AES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = aes_encrypt_library(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'aes_manual':
            if not key:
                return jsonify({'error': 'AES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = aes_encrypt_manual(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'des_library':
            if not key:
                return jsonify({'error': 'DES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = des_encrypt_library(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'des_manual':
            if not key:
                return jsonify({'error': 'DES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = des_encrypt_manual(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rsa_library':
            # For RSA, key should be public key in PEM format
            if not key:
                return jsonify({'error': 'RSA için public key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = rsa_encrypt_library(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'dsa_library':
            # For DSA, key should be public key in PEM format
            if not key:
                return jsonify({'error': 'DSA için public key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = dsa_encrypt_library(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'ecc_library':
            # For ECC, key should be public key in PEM format
            if not key:
                return jsonify({'error': 'ECC için public key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                encrypted = ecc_encrypt_library(message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'encrypted_message': encrypted,
                    'original_message': message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        else:
            return jsonify({'error': f'Bilinmeyen şifreleme türü: {cipher_type}'}), 400
        
        return jsonify({
            'success': True,
            'encrypted_message': encrypted,
            'original_message': message
        })
    
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """API endpoint for decryption"""
    try:
        data = request.get_json()
        encrypted_message = data.get('encrypted_message', '')
        cipher_type = data.get('cipher_type', '').lower()
        key = data.get('key', '')
        
        if not encrypted_message:
            return jsonify({'error': 'Şifrelenmiş mesaj boş olamaz'}), 400
        
        if cipher_type == 'caesar':
            try:
                shift = int(key)
                decrypted = caesar_decrypt(encrypted_message, shift)
            except ValueError:
                return jsonify({'error': 'Geçersiz kaydırma değeri. Tam sayı olmalıdır.'}), 400
        
        elif cipher_type == 'hill':
            try:
                key_matrix = parse_hill_key(key)
                decrypted = hill_decrypt(encrypted_message, key_matrix)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        elif cipher_type == 'vigenere':
            if not key:
                return jsonify({'error': 'Vigenere şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = vigenere_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'vernam':
            if not key:
                return jsonify({'error': 'Vernam şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = vernam_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'playfair':
            if not key:
                return jsonify({'error': 'Playfair şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = playfair_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'route':
            if not key:
                return jsonify({'error': 'Route şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = route_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'affine':
            if not key:
                return jsonify({'error': 'Affine şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = affine_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rail_fence':
            if not key:
                return jsonify({'error': 'Rail Fence şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = rail_fence_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'columnar':
            if not key:
                return jsonify({'error': 'Columnar şifresi için anahtar boş olamaz'}), 400
            try:
                decrypted = columnar_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'aes_library':
            if not key:
                return jsonify({'error': 'AES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = aes_decrypt_library(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'aes_manual':
            if not key:
                return jsonify({'error': 'AES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = aes_decrypt_manual(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'des_library':
            if not key:
                return jsonify({'error': 'DES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = des_decrypt_library(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'des_manual':
            if not key:
                return jsonify({'error': 'DES için anahtar boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = des_decrypt_manual(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rsa_library':
            # For RSA, key should be private key in PEM format
            if not key:
                return jsonify({'error': 'RSA için private key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = rsa_decrypt_library(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'dsa_library':
            # For DSA, key should be private key in PEM format
            if not key:
                return jsonify({'error': 'DSA için private key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = dsa_decrypt_library(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'ecc_library':
            # For ECC, key should be private key in PEM format
            if not key:
                return jsonify({'error': 'ECC için private key boş olamaz'}), 400
            try:
                start_time = time.perf_counter()
                decrypted = ecc_decrypt_library(encrypted_message, key)
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return jsonify({
                    'success': True,
                    'decrypted_message': decrypted,
                    'encrypted_message': encrypted_message,
                    'execution_time_ms': round(execution_time, 4)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        else:
            return jsonify({'error': f'Bilinmeyen şifreleme türü: {cipher_type}'}), 400
        
        return jsonify({
            'success': True,
            'decrypted_message': decrypted,
            'encrypted_message': encrypted_message
        })
    
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


