"""
Flask web server for encryption/decryption
"""

from flask import Flask, render_template, request, jsonify
import numpy as np
import json
import re
from cipher_utils import (
    caesar_encrypt, caesar_decrypt,
    hill_encrypt, hill_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    vernam_encrypt, vernam_decrypt,
    playfair_encrypt, playfair_decrypt,
    route_encrypt, route_decrypt,
    affine_encrypt, affine_decrypt,
    rail_fence_encrypt, rail_fence_decrypt,
    columnar_encrypt, columnar_decrypt
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


@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """API endpoint for encryption"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        cipher_type = data.get('cipher_type', '').lower()
        key = data.get('key', '')
        
        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        if cipher_type == 'caesar':
            try:
                shift = int(key)
                encrypted = caesar_encrypt(message, shift)
            except ValueError:
                return jsonify({'error': 'Invalid shift value. Must be an integer.'}), 400
        
        elif cipher_type == 'hill':
            try:
                key_matrix = parse_hill_key(key)
                encrypted = hill_encrypt(message, key_matrix)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        elif cipher_type == 'vigenere':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Vigenere cipher'}), 400
            try:
                encrypted = vigenere_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'vernam':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Vernam cipher'}), 400
            try:
                encrypted = vernam_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'playfair':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Playfair cipher'}), 400
            try:
                encrypted = playfair_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'route':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Route cipher'}), 400
            try:
                encrypted = route_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'affine':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Affine cipher'}), 400
            try:
                encrypted = affine_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rail_fence':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Rail Fence cipher'}), 400
            try:
                encrypted = rail_fence_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'columnar':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Columnar cipher'}), 400
            try:
                encrypted = columnar_encrypt(message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        else:
            return jsonify({'error': f'Unknown cipher type: {cipher_type}'}), 400
        
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
            return jsonify({'error': 'Encrypted message cannot be empty'}), 400
        
        if cipher_type == 'caesar':
            try:
                shift = int(key)
                decrypted = caesar_decrypt(encrypted_message, shift)
            except ValueError:
                return jsonify({'error': 'Invalid shift value. Must be an integer.'}), 400
        
        elif cipher_type == 'hill':
            try:
                key_matrix = parse_hill_key(key)
                decrypted = hill_decrypt(encrypted_message, key_matrix)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        elif cipher_type == 'vigenere':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Vigenere cipher'}), 400
            try:
                decrypted = vigenere_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'vernam':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Vernam cipher'}), 400
            try:
                decrypted = vernam_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'playfair':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Playfair cipher'}), 400
            try:
                decrypted = playfair_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'route':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Route cipher'}), 400
            try:
                decrypted = route_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'affine':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Affine cipher'}), 400
            try:
                decrypted = affine_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'rail_fence':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Rail Fence cipher'}), 400
            try:
                decrypted = rail_fence_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        elif cipher_type == 'columnar':
            if not key:
                return jsonify({'error': 'Key cannot be empty for Columnar cipher'}), 400
            try:
                decrypted = columnar_decrypt(encrypted_message, key)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        else:
            return jsonify({'error': f'Unknown cipher type: {cipher_type}'}), 400
        
        return jsonify({
            'success': True,
            'decrypted_message': decrypted,
            'encrypted_message': encrypted_message
        })
    
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


