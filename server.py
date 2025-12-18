"""
Server that receives encrypted messages and decrypts them
"""

import socket
import json
import numpy as np
from cipher_utils import (
    caesar_decrypt,
    hill_decrypt,
    vigenere_decrypt,
    vernam_decrypt,
    playfair_decrypt,
    route_decrypt,
    affine_decrypt,
    rail_fence_decrypt,
    columnar_decrypt,
)


def parse_hill_key(key_str):
    """
    Parse Hill cipher key from string format
    Expected format: "[[a,b],[c,d]]" for 2x2 or "[[a,b,c],[d,e,f],[g,h,i]]" for 3x3
    """
    try:
        key_list = json.loads(key_str)
        key_matrix = np.array(key_list)
        if key_matrix.shape not in [(2, 2), (3, 3)]:
            raise ValueError("Key matrix must be 2x2 or 3x3")
        return key_matrix
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid key format: {e}")


def decrypt_message(encrypted_message, cipher_type, key):
    """
    Decrypt message based on cipher type
    
    Args:
        encrypted_message: The encrypted message
        cipher_type: 'caesar', 'hill', or 'vigenere'
        key: The decryption key (format depends on cipher type)
    
    Returns:
        Decrypted message
    """
    try:
        if cipher_type.lower() == 'caesar':
            shift = int(key)
            return caesar_decrypt(encrypted_message, shift)
        
        elif cipher_type.lower() == 'hill':
            key_matrix = parse_hill_key(key)
            return hill_decrypt(encrypted_message, key_matrix)
        
        elif cipher_type.lower() == 'vigenere':
            return vigenere_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'vernam':
            return vernam_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'playfair':
            return playfair_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'route':
            return route_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'affine':
            return affine_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'rail_fence':
            return rail_fence_decrypt(encrypted_message, key)

        elif cipher_type.lower() == 'columnar':
            return columnar_decrypt(encrypted_message, key)
        
        else:
            return f"Error: Unknown cipher type '{cipher_type}'"
    
    except Exception as e:
        return f"Error decrypting message: {str(e)}"


def start_server(host='localhost', port=12345):
    """
    Start the server to receive and decrypt messages
    """
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind to address
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Server listening on {host}:{port}")
        print("Waiting for encrypted messages...")
        
        while True:
            # Accept connection
            client_socket, client_address = server_socket.accept()
            print(f"\nConnection established with {client_address}")
            
            try:
                # Receive data
                data = client_socket.recv(4096).decode('utf-8')
                
                if not data:
                    continue
                
                # Parse JSON message
                message_data = json.loads(data)
                encrypted_message = message_data.get('message', '')
                cipher_type = message_data.get('cipher_type', '')
                key = message_data.get('key', '')
                
                print(f"Received encrypted message: {encrypted_message}")
                print(f"Cipher type: {cipher_type}")
                print(f"Key: {key}")
                
                # Decrypt message
                decrypted_message = decrypt_message(encrypted_message, cipher_type, key)
                
                print(f"Decrypted message: {decrypted_message}")
                
                # Send response back to client
                response = {
                    'status': 'success',
                    'decrypted_message': decrypted_message
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                
            except json.JSONDecodeError:
                error_response = {
                    'status': 'error',
                    'message': 'Invalid JSON format'
                }
                client_socket.send(json.dumps(error_response).encode('utf-8'))
            
            except Exception as e:
                error_response = {
                    'status': 'error',
                    'message': str(e)
                }
                client_socket.send(json.dumps(error_response).encode('utf-8'))
                print(f"Error: {e}")
            
            finally:
                client_socket.close()
                print(f"Connection with {client_address} closed")
    
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    
    finally:
        server_socket.close()


if __name__ == '__main__':
    start_server()


