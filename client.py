"""
Client program for PUF-RLWE authentication system.
Simulates IoT device with PUF and communicates securely with server.
"""

import socket
import json
import secrets
from typing import Optional, Dict
from crypto_utils import PUF, RLWE
from authentication import PUF_RLWE_Authenticator, SessionManager


class AuthenticationClient:
    """Client for PUF-RLWE authentication and secure communication."""
    
    def __init__(self, device_id: str, server_host: str = 'localhost', 
                 server_port: int = 8888):
        """Initialize client with device ID."""
        self.device_id = device_id
        self.server_host = server_host
        self.server_port = server_port
        
        # Initialize PUF (simulates hardware PUF)
        self.puf = PUF()
        
        # Initialize RLWE and authenticator
        self.rlwe = RLWE(n=256, q=7681)
        self.authenticator = PUF_RLWE_Authenticator()
        
        # Session management
        self.session_id = None
        self.session_manager = SessionManager()
        
        # Connection
        self.socket = None
        self.connected = False
    
    def connect(self) -> bool:
        """Connect to server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            print(f"[CLIENT] Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[CLIENT] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        if self.connected:
            try:
                # Send disconnect message
                request = {'type': 'disconnect'}
                self.send_message(json.dumps(request))
                response = self.receive_message()
                
            except Exception as e:
                print(f"[CLIENT] Error during disconnect: {e}")
            finally:
                if self.socket:
                    self.socket.close()
                self.connected = False
                print("[CLIENT] Disconnected from server")
    
    def enroll(self) -> bool:
        """Enroll device with server."""
        if not self.connected:
            print("[CLIENT] Not connected to server")
            return False
        
        try:
            print(f"[CLIENT] Enrolling device: {self.device_id}")
            
            import time
            start_time = time.time()
            
            # Generate enrollment data using PUF
            enrollment_data = self.authenticator.enrollment(self.puf, self.device_id)
            
            # Send enrollment request
            request = {
                'type': 'enroll',
                'device_id': self.device_id,
                'enrollment_data': enrollment_data
            }
            
            self.send_message(json.dumps(request))
            
            # Receive response
            response_data = self.receive_message()
            response = json.loads(response_data)
            
            elapsed = time.time() - start_time
            
            if response.get('status') == 'success':
                print(f"[CLIENT] Enrollment successful! (took {elapsed*1000:.2f}ms)")
                return True
            else:
                print(f"[CLIENT] Enrollment failed: {response.get('message')}")
                return False
                
        except Exception as e:
            print(f"[CLIENT] Enrollment error: {e}")
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with server."""
        if not self.connected:
            print("[CLIENT] Not connected to server")
            return False
        
        try:
            import time
            print(f"[CLIENT] Authenticating device: {self.device_id}")
            
            auth_start = time.time()
            
            # Send authentication request
            request = {
                'type': 'authenticate',
                'device_id': self.device_id
            }
            
            self.send_message(json.dumps(request))
            
            # Receive challenge
            response_data = self.receive_message()
            response = json.loads(response_data)
            
            if response.get('status') == 'challenge':
                challenge = bytes.fromhex(response['challenge'])
                nonce = bytes.fromhex(response['nonce'])
                crp_index = response['crp_index']
                helper_data_hex = response.get('helper_data')
                
                print("[CLIENT] Received authentication challenge")
                
                # Get helper data if provided
                helper_data = bytes.fromhex(helper_data_hex) if helper_data_hex else b''
                
                response_start = time.time()
                # Create authentication response using PUF with fuzzy extractor
                auth_response = self.authenticator.create_auth_response(
                    self.puf, challenge, nonce, helper_data
                )
                response_time = time.time() - response_start
                
                # Send authentication response
                auth_request = {
                    'type': 'authenticate',
                    'device_id': self.device_id,
                    'challenge': challenge.hex(),
                    'nonce': nonce.hex(),
                    'crp_index': crp_index,
                    'auth_response': auth_response
                }
                
                self.send_message(json.dumps(auth_request))
                
                # Receive authentication result
                result_data = self.receive_message()
                result = json.loads(result_data)
                
                total_time = time.time() - auth_start
                
                if result.get('status') == 'success':
                    self.session_id = result.get('session_id')
                    
                    # Store session information from server
                    session_public_key_data = result.get('session_public_key')
                    session_private_key_data = result.get('session_private_key')
                    session_key_hex = result.get('session_key')
                    
                    if session_public_key_data and session_private_key_data and session_key_hex:
                        import numpy as np
                        # Store session data for encryption
                        self.session_data = {
                            'device_id': self.device_id,
                            'session_key': bytes.fromhex(session_key_hex),
                            'public_key': (
                                np.array(session_public_key_data[0], dtype=np.int64),
                                np.array(session_public_key_data[1], dtype=np.int64)
                            ),
                            'private_key': np.array(session_private_key_data, dtype=np.int64),
                            'timestamp': secrets.token_hex(16)
                        }
                        # Register in session manager
                        self.session_manager.sessions[self.session_id] = self.session_data
                    
                    print("[CLIENT] Authentication successful!")
                    print(f"[CLIENT] Session ID: {self.session_id[:16]}...")
                    print(f"[PERF] Response generation: {response_time*1000:.2f}ms")
                    print(f"[PERF] Total authentication: {total_time*1000:.2f}ms")
                    return True
                else:
                    print(f"[CLIENT] Authentication failed: {result.get('message')}")
                    return False
            else:
                print(f"[CLIENT] Unexpected response: {response.get('message')}")
                return False
                
        except Exception as e:
            print(f"[CLIENT] Authentication error: {e}")
            return False
    
    def send_secure_message(self, message: str) -> bool:
        """Send encrypted message to server."""
        if not self.session_id:
            print("[CLIENT] Not authenticated")
            return False
        
        try:
            print(f"[CLIENT] Sending secure message: {message}")
            
            # Encrypt message using RLWE session
            encrypted = self.session_manager.encrypt_message(
                self.session_id, message.encode(), self.rlwe
            )
            
            if encrypted is None:
                print("[CLIENT] Encryption failed")
                return False
            
            # Send encrypted message
            request = {
                'type': 'secure_message',
                'session_id': self.session_id,
                'encrypted_message': encrypted
            }
            
            self.send_message(json.dumps(request))
            
            # Receive response
            response_data = self.receive_message()
            response = json.loads(response_data)
            
            if response.get('status') == 'success':
                print("[CLIENT] Message sent successfully")
                
                # Decrypt response if present
                encrypted_response = response.get('encrypted_response')
                if encrypted_response:
                    decrypted = self.session_manager.decrypt_message(
                        self.session_id, encrypted_response, self.rlwe
                    )
                    if decrypted:
                        print(f"[CLIENT] Server response: {decrypted.decode('utf-8', errors='replace')}")
                    else:
                        print("[CLIENT] Could not decrypt server response")
                
                return True
            else:
                print(f"[CLIENT] Message failed: {response.get('message')}")
                return False
                
        except Exception as e:
            print(f"[CLIENT] Secure message error: {e}")
            return False
    
    def send_message(self, message: str):
        """Send message to server with length prefix."""
        message_bytes = message.encode('utf-8')
        length = len(message_bytes)
        self.socket.sendall(length.to_bytes(4, byteorder='big'))
        self.socket.sendall(message_bytes)
    
    def receive_message(self) -> Optional[str]:
        """Receive message from server with length prefix."""
        try:
            # Receive length prefix
            length_bytes = self.receive_all(4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive message
            message_bytes = self.receive_all(length)
            if not message_bytes:
                return None
            
            return message_bytes.decode('utf-8')
            
        except Exception as e:
            print(f"[CLIENT] Error receiving message: {e}")
            return None
    
    def receive_all(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from socket."""
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)


def interactive_client():
    """Run interactive client."""
    print("=" * 60)
    print("PUF-RLWE Authentication Client")
    print("=" * 60)
    
    # Get device ID
    device_id = input("Enter device ID (or press Enter for default): ").strip()
    if not device_id:
        device_id = f"device_{secrets.token_hex(4)}"
    
    print(f"\nDevice ID: {device_id}")
    
    # Get server address
    server_host = input("Enter server host (default: localhost): ").strip()
    if not server_host:
        server_host = 'localhost'
    
    server_port = input("Enter server port (default: 8888): ").strip()
    if not server_port:
        server_port = 8888
    else:
        server_port = int(server_port)
    
    # Create client
    client = AuthenticationClient(device_id, server_host, server_port)
    
    # Connect to server
    if not client.connect():
        return
    
    try:
        # Main menu
        while True:
            print("\n" + "=" * 60)
            print("Commands:")
            print("  1. Enroll device")
            print("  2. Authenticate")
            print("  3. Send secure message")
            print("  4. Show performance metrics")
            print("  5. Disconnect and exit")
            print("=" * 60)
            
            choice = input("Enter choice: ").strip()
            
            if choice == '1':
                client.enroll()
                
            elif choice == '2':
                client.authenticate()
                
            elif choice == '3':
                if not client.session_id:
                    print("[CLIENT] Please authenticate first")
                else:
                    message = input("Enter message to send: ")
                    client.send_secure_message(message)
            
            elif choice == '4':
                client.authenticator.metrics.print_summary()
                    
            elif choice == '5':
                client.disconnect()
                break
                
            else:
                print("Invalid choice")
                
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted by user")
    finally:
        if client.connected:
            client.disconnect()


def demo_client():
    """Run automated demo client."""
    print("=" * 60)
    print("PUF-RLWE Authentication Client - Demo Mode")
    print("=" * 60)
    
    device_id = f"demo_device_{secrets.token_hex(4)}"
    client = AuthenticationClient(device_id, 'localhost', 8888)
    
    try:
        # Connect
        if not client.connect():
            return
        
        # Enroll
        print("\n[DEMO] Step 1: Enrolling device...")
        if not client.enroll():
            return
        
        # Authenticate
        print("\n[DEMO] Step 2: Authenticating...")
        if not client.authenticate():
            return
        
        # Send messages
        print("\n[DEMO] Step 3: Sending secure messages...")
        messages = [
            "Hello, Server!",
            "This is a secure message using PUF-RLWE.",
            "Testing enhanced polynomial multiplication."
        ]
        
        for msg in messages:
            client.send_secure_message(msg)
            import time
            time.sleep(1)
        
        # Disconnect
        print("\n[DEMO] Step 4: Disconnecting...")
        client.disconnect()
        
        print("\n[DEMO] Demo completed successfully!")
        
    except Exception as e:
        print(f"[DEMO] Error: {e}")
    finally:
        if client.connected:
            client.disconnect()


def main():
    """Main entry point."""
    print("Select mode:")
    print("  1. Interactive mode")
    print("  2. Demo mode")
    
    choice = input("Enter choice: ").strip()
    
    if choice == '1':
        interactive_client()
    elif choice == '2':
        demo_client()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
