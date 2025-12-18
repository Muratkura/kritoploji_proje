"""
Client that encrypts messages and sends them to the server
"""

import socket
import json
import numpy as np
from cipher_utils import (
    caesar_encrypt,
    hill_encrypt,
    vigenere_encrypt,
    vernam_encrypt,
    playfair_encrypt,
    route_encrypt,
    affine_encrypt,
    rail_fence_encrypt,
    columnar_encrypt,
)


def parse_hill_key(key_str):
    """
    Parse Hill cipher key from string format
    Expected format: "[[a,b],[c,d]]" for 2x2 or "[[a,b,c],[d,e,f],[g,h,i]]" for 3x3
    Or can accept list directly
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


def encrypt_message(message, cipher_type, key):
    """
    Encrypt message based on cipher type
    
    Args:
        message: The plain text message
        cipher_type: 'caesar', 'hill', or 'vigenere'
        key: The encryption key (format depends on cipher type)
    
    Returns:
        Encrypted message
    """
    try:
        if cipher_type.lower() == 'caesar':
            shift = int(key)
            return caesar_encrypt(message, shift)
        
        elif cipher_type.lower() == 'hill':
            key_matrix = parse_hill_key(key)
            return hill_encrypt(message, key_matrix)
        
        elif cipher_type.lower() == 'vigenere':
            return vigenere_encrypt(message, key)

        elif cipher_type.lower() == 'vernam':
            return vernam_encrypt(message, key)

        elif cipher_type.lower() == 'playfair':
            return playfair_encrypt(message, key)

        elif cipher_type.lower() == 'route':
            return route_encrypt(message, key)

        elif cipher_type.lower() == 'affine':
            return affine_encrypt(message, key)

        elif cipher_type.lower() == 'rail_fence':
            return rail_fence_encrypt(message, key)

        elif cipher_type.lower() == 'columnar':
            return columnar_encrypt(message, key)
        
        else:
            raise ValueError(f"Unknown cipher type '{cipher_type}'")
    
    except Exception as e:
        raise ValueError(f"Error encrypting message: {str(e)}")


def send_message(host='localhost', port=12345, message='', cipher_type='caesar', key=''):
    """
    Send encrypted message to server
    
    Args:
        host: Server hostname
        port: Server port
        message: Plain text message to encrypt and send
        cipher_type: 'caesar', 'hill', or 'vigenere'
        key: Encryption key
    """
    # Encrypt message
    try:
        encrypted_message = encrypt_message(message, cipher_type, key)
        print(f"Original message: {message}")
        print(f"Encrypted message: {encrypted_message}")
    except Exception as e:
        print(f"Encryption error: {e}")
        return
    
    # Create socket and connect
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))
        
        # Prepare message data
        message_data = {
            'message': encrypted_message,
            'cipher_type': cipher_type,
            'key': str(key) if not isinstance(key, (list, np.ndarray)) else json.dumps(key.tolist() if isinstance(key, np.ndarray) else key)
        }
        
        # Send encrypted message
        client_socket.send(json.dumps(message_data).encode('utf-8'))
        
        # Receive response
        response = client_socket.recv(4096).decode('utf-8')
        response_data = json.loads(response)
        
        if response_data.get('status') == 'success':
            print(f"Server decrypted message: {response_data.get('decrypted_message')}")
        else:
            print(f"Server error: {response_data.get('message')}")
    
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {host}:{port}")
        print("Make sure the server is running!")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        client_socket.close()


def interactive_mode():
    """
    Interactive mode for sending messages
    """
    print("=" * 50)
    print("Encrypted Message Client")
    print("=" * 50)
    print("\nAvailable ciphers: caesar, hill, vigenere, vernam, playfair, route, affine, rail_fence, columnar")
    print("Type 'quit' to exit\n")
    
    host = input("Enter server host (default: localhost): ").strip() or 'localhost'
    port_input = input("Enter server port (default: 12345): ").strip()
    port = int(port_input) if port_input else 12345
    
    while True:
        print("\n" + "-" * 50)
        message = input("Enter message to encrypt: ").strip()
        
        if message.lower() == 'quit':
            print("Goodbye!")
            break
        
        if not message:
            print("Message cannot be empty!")
            continue
        
        cipher_type = input("Enter cipher type (caesar/hill/vigenere/vernam/playfair/route/affine/rail_fence/columnar): ").strip().lower()
        
        if cipher_type not in ['caesar', 'hill', 'vigenere', 'vernam', 'playfair', 'route', 'affine', 'rail_fence', 'columnar']:
            print("Invalid cipher type! Please choose one of: caesar, hill, vigenere, vernam, playfair, route, affine, rail_fence, columnar")
            continue
        
        # Get key based on cipher type
        if cipher_type == 'caesar':
            key_input = input("Enter shift value (integer): ").strip()
            try:
                key = int(key_input)
            except ValueError:
                print("Invalid shift value! Must be an integer.")
                continue
        
        elif cipher_type == 'hill':
            print("Enter key matrix as JSON array:")
            print("  For 2x2: [[a,b],[c,d]]")
            print("  For 3x3: [[a,b,c],[d,e,f],[g,h,i]]")
            key_input = input("Key matrix: ").strip()
            try:
                key = json.loads(key_input)
            except json.JSONDecodeError:
                print("Invalid key format! Must be valid JSON array.")
                continue
        
        elif cipher_type == 'vigenere':
            key = input("Enter key string: ").strip()
            if not key:
                print("Key cannot be empty!")
                continue

        elif cipher_type == 'vernam':
            key = input("Enter key string (letters): ").strip()
            if not key:
                print("Key cannot be empty!")
                continue

        elif cipher_type == 'playfair':
            key = input("Enter key string: ").strip()
            if not key:
                print("Key cannot be empty!")
                continue

        elif cipher_type == 'route':
            key_input = input("Enter column count (integer): ").strip()
            try:
                key = int(key_input)
            except ValueError:
                print("Invalid column count! Must be an integer.")
                continue

        elif cipher_type == 'affine':
            key = input("Enter key as a,b (e.g. 5,8): ").strip()
            if not key:
                print("Key cannot be empty!")
                continue

        elif cipher_type == 'rail_fence':
            key_input = input("Enter rails (integer >=2): ").strip()
            try:
                key = int(key_input)
            except ValueError:
                print("Invalid rails value! Must be an integer.")
                continue

        elif cipher_type == 'columnar':
            key = input("Enter keyword (>=2 chars): ").strip()
            if not key or len(key) < 2:
                print("Key must be at least 2 characters!")
                continue
        
        # Send message
        send_message(host, port, message, cipher_type, key)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        # Command line mode
        if len(sys.argv) < 5:
            print("Usage: python client.py <message> <cipher_type> <key> [host] [port]")
            print("Example: python client.py 'Hello World' caesar 3")
            print("Example: python client.py 'Hello' hill '[[3,3],[2,5]]'")
            print("Example: python client.py 'Hello' vigenere 'KEY'")
            print("Example: python client.py 'Hello' vernam 'SECRET'")
            print("Example: python client.py 'HELLO' playfair 'MONARCHY'")
            print("Example: python client.py 'Hello World' route 5")
            print("Example: python client.py 'Hello' affine '5,8'")
            print("Example: python client.py 'Hello World' rail_fence 3")
            print("Example: python client.py 'Hello World' columnar 'ZEBRA'")
            sys.exit(1)
        
        message = sys.argv[1]
        cipher_type = sys.argv[2]
        key = sys.argv[3]
        host = sys.argv[4] if len(sys.argv) > 4 else 'localhost'
        port = int(sys.argv[5]) if len(sys.argv) > 5 else 12345
        
        send_message(host, port, message, cipher_type, key)
    else:
        # Interactive mode
        interactive_mode()


