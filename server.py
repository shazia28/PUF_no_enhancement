"""
Server program for PUF-RLWE authentication system.
Handles client connections, authentication, and secure messaging.
"""

import socket
import json
import secrets
import threading
import time
from typing import Dict, Optional
from crypto_utils import RLWE
from authentication import PUF_RLWE_Authenticator, SessionManager


class AuthenticationServer:
    """Server for handling PUF-RLWE authentication and secure communication."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        """Initialize server."""
        self.host = host
        self.port = port
        self.rlwe = RLWE(n=256, q=7681)
        self.authenticator = PUF_RLWE_Authenticator()
        self.session_manager = SessionManager()
        
        # Storage for enrolled devices
        self.enrolled_devices: Dict[str, Dict] = {}
        
        # Active connections
        self.active_connections = {}
        
        self.running = False
        self.server_socket = None
        
    def start(self):
        """Start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.running = True
        print(f"[SERVER] Started on {self.host}:{self.port}")
        print(f"[SERVER] Waiting for connections...")
        
        try:
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, address = self.server_socket.accept()
                    print(f"[SERVER] New connection from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[SERVER] Error accepting connection: {e}")
                    
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[SERVER] Stopped")
    
    def handle_client(self, client_socket: socket.socket, address):
        """Handle individual client connection."""
        device_id = None
        session_id = None
        
        try:
            while self.running:
                # Receive message from client
                data = self.receive_message(client_socket)
                if not data:
                    break
                
                request = json.loads(data)
                request_type = request.get('type')
                
                print(f"[SERVER] Received request: {request_type} from {address}")
                
                # Handle different request types
                if request_type == 'enroll':
                    response = self.handle_enrollment(request)
                    
                elif request_type == 'authenticate':
                    response, session_id, device_id = self.handle_authentication(request)
                    
                elif request_type == 'secure_message':
                    if not session_id:
                        response = {'status': 'error', 'message': 'Not authenticated'}
                    else:
                        response = self.handle_secure_message(request, session_id)
                        
                elif request_type == 'disconnect':
                    if session_id:
                        self.session_manager.close_session(session_id)
                    response = {'status': 'success', 'message': 'Disconnected'}
                    self.send_message(client_socket, json.dumps(response))
                    break
                    
                else:
                    response = {'status': 'error', 'message': 'Unknown request type'}
                
                # Send response
                self.send_message(client_socket, json.dumps(response))
                
        except Exception as e:
            print(f"[SERVER] Error handling client {address}: {e}")
        finally:
            if session_id:
                self.session_manager.close_session(session_id)
            client_socket.close()
            print(f"[SERVER] Connection closed: {address}")
    
    def handle_enrollment(self, request: Dict) -> Dict:
        """Handle device enrollment request."""
        try:
            device_id = request.get('device_id')
            enrollment_data = request.get('enrollment_data')
            
            if not device_id or not enrollment_data:
                return {'status': 'error', 'message': 'Missing enrollment data'}
            
            # Store enrollment data
            self.enrolled_devices[device_id] = enrollment_data
            
            print(f"[SERVER] Device enrolled: {device_id}")
            print(f"[SERVER] Total enrolled devices: {len(self.enrolled_devices)}")
            
            return {
                'status': 'success',
                'message': 'Device enrolled successfully',
                'device_id': device_id
            }
            
        except Exception as e:
            return {'status': 'error', 'message': f'Enrollment failed: {str(e)}'}
    
    def handle_authentication(self, request: Dict) -> tuple:
        """Handle authentication request."""
        try:
            device_id = request.get('device_id')
            
            if device_id not in self.enrolled_devices:
                return ({'status': 'error', 'message': 'Device not enrolled'}, None, None)
            
            enrollment_data = self.enrolled_devices[device_id]
            
            # Generate challenge
            challenge, crp_index = self.authenticator.generate_auth_challenge(enrollment_data)
            nonce = secrets.token_bytes(32)
            
            # Get helper data for fuzzy extractor
            helper_data_hex = enrollment_data['crps'][crp_index].get('helper_data', '')
            
            # Send challenge to client
            challenge_response = {
                'status': 'challenge',
                'challenge': challenge.hex(),
                'nonce': nonce.hex(),
                'crp_index': crp_index,
                'helper_data': helper_data_hex  # Send helper data for fuzzy extraction
            }
            
            # Wait for auth response (this is simplified; in practice would be separate request)
            auth_response = request.get('auth_response')
            
            if not auth_response:
                # First phase: send challenge
                return (challenge_response, None, None)
            
            # Second phase: verify response
            verified = self.authenticator.verify_auth_response(
                enrollment_data,
                request.get('crp_index'),
                bytes.fromhex(request.get('challenge')),
                auth_response,
                bytes.fromhex(request.get('nonce'))
            )
            
            if verified:
                # Create session
                session_id, session_data = self.session_manager.create_session(
                    device_id, self.rlwe
                )
                
                print(f"[SERVER] Authentication successful: {device_id}")
                
                public_key_a = session_data['public_key'][0].tolist()
                public_key_b = session_data['public_key'][1].tolist()
                private_key = session_data['private_key'].tolist()
                
                return ({
                    'status': 'success',
                    'message': 'Authentication successful',
                    'session_id': session_id,
                    'session_public_key': (public_key_a, public_key_b),
                    'session_private_key': private_key,
                    'session_key': session_data['session_key'].hex()
                }, session_id, device_id)
            else:
                print(f"[SERVER] Authentication failed: {device_id}")
                return ({'status': 'error', 'message': 'Authentication failed'}, None, None)
                
        except Exception as e:
            return ({'status': 'error', 'message': f'Authentication error: {str(e)}'}, None, None)
    
    def handle_secure_message(self, request: Dict, session_id: str) -> Dict:
        """Handle encrypted message from authenticated client."""
        try:
            encrypted_message = request.get('encrypted_message')
            
            if not encrypted_message:
                return {'status': 'error', 'message': 'No message provided'}
            
            # Decrypt message using RLWE session
            decrypted = self.session_manager.decrypt_message(
                session_id, encrypted_message, self.rlwe
            )
            
            if decrypted is None:
                return {'status': 'error', 'message': 'Decryption failed'}
            
            print(f"[SERVER] Received secure message: {decrypted.decode('utf-8', errors='replace')}")
            
            # Echo response (encrypt and send back)
            response_msg = f"Server received: {decrypted.decode('utf-8', errors='replace')}"
            encrypted_response = self.session_manager.encrypt_message(
                session_id, response_msg.encode(), self.rlwe
            )
            
            return {
                'status': 'success',
                'message': 'Message received',
                'encrypted_response': encrypted_response
            }
            
        except Exception as e:
            return {'status': 'error', 'message': f'Message handling error: {str(e)}'}
    
    def send_message(self, client_socket: socket.socket, message: str):
        """Send message to client with length prefix."""
        message_bytes = message.encode('utf-8')
        length = len(message_bytes)
        client_socket.sendall(length.to_bytes(4, byteorder='big'))
        client_socket.sendall(message_bytes)
    
    def receive_message(self, client_socket: socket.socket) -> Optional[str]:
        """Receive message from client with length prefix."""
        try:
            # Receive length prefix
            length_bytes = self.receive_all(client_socket, 4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive message
            message_bytes = self.receive_all(client_socket, length)
            if not message_bytes:
                return None
            
            return message_bytes.decode('utf-8')
            
        except Exception as e:
            print(f"[SERVER] Error receiving message: {e}")
            return None
    
    def receive_all(self, client_socket: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from socket."""
        data = bytearray()
        while len(data) < n:
            packet = client_socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
    
    def list_enrolled_devices(self):
        """List all enrolled devices."""
        print("\n[SERVER] Enrolled Devices:")
        if not self.enrolled_devices:
            print("  No devices enrolled")
        else:
            for device_id in self.enrolled_devices:
                print(f"  - {device_id}")
        print()


def main():
    """Run the server."""
    print("=" * 60)
    print("PUF-RLWE Authentication Server")
    print("=" * 60)
    
    server = AuthenticationServer(host='0.0.0.0', port=8888)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Interrupted by user")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
