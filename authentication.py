"""
New authentication method combining PUF and RLWE for secure device authentication.
"""

import hashlib
import secrets
import numpy as np
import json
import time
from typing import Tuple, Dict, Optional
from crypto_utils import PUF, RLWE, bytes_to_poly, poly_to_bytes


class PerformanceMetrics:
    """Track performance metrics for authentication operations."""
    
    def __init__(self):
        self.metrics = {
            'enrollment': [],
            'authentication': [],
            'encryption': [],
            'decryption': [],
            'signature_generation': [],
            'signature_verification': []
        }
    
    def record(self, operation: str, duration: float, data_size: int = 0):
        """Record a performance measurement."""
        self.metrics[operation].append({
            'duration': duration,
            'data_size': data_size,
            'timestamp': time.time()
        })
    
    def get_stats(self, operation: str) -> Dict:
        """Get statistics for an operation."""
        if not self.metrics[operation]:
            return {'count': 0}
        
        durations = [m['duration'] for m in self.metrics[operation]]
        return {
            'count': len(durations),
            'total_time': sum(durations),
            'avg_time': sum(durations) / len(durations),
            'min_time': min(durations),
            'max_time': max(durations),
            'throughput': len(durations) / sum(durations) if sum(durations) > 0 else 0
        }
    
    def print_summary(self):
        """Print performance summary."""
        print("\n" + "=" * 60)
        print("PERFORMANCE METRICS SUMMARY")
        print("=" * 60)
        
        for operation in ['enrollment', 'authentication', 'encryption', 
                         'decryption', 'signature_generation', 'signature_verification']:
            stats = self.get_stats(operation)
            if stats['count'] > 0:
                print(f"\n{operation.upper().replace('_', ' ')}:")
                print(f"  Operations: {stats['count']}")
                print(f"  Total Time: {stats['total_time']:.4f}s")
                print(f"  Avg Time:   {stats['avg_time']*1000:.2f}ms")
                print(f"  Min Time:   {stats['min_time']*1000:.2f}ms")
                print(f"  Max Time:   {stats['max_time']*1000:.2f}ms")
                print(f"  Throughput: {stats['throughput']:.2f} ops/sec")
        
        print("\n" + "=" * 60)


class PUF_RLWE_Authenticator:
    """
    Novel authentication protocol combining PUF and RLWE.
    
    Protocol Overview:
    1. Enrollment Phase: Device registers its PUF responses encrypted with RLWE
    2. Authentication Phase: Server challenges device, device responds with PUF-RLWE proof
    3. Verification Phase: Server verifies response using stored encrypted PUF data
    """
    
    def __init__(self, n: int = 256, q: int = 7681):
        """Initialize authenticator with RLWE parameters."""
        self.rlwe = RLWE(n=n, q=q)
        self.n = n
        self.q = q
        self.metrics = PerformanceMetrics()
        
    def enrollment(self, puf: PUF, device_id: str) -> Dict:
        """
        Enrollment phase: Register a device with its PUF characteristics.
        
        Returns enrollment data to be stored by the server.
        """
        start_time = time.time()
        
        # Generate multiple challenge-response pairs
        num_crps = 10  # Number of Challenge-Response Pairs
        crps = []
        
        for i in range(num_crps):
            # Generate random challenge
            challenge = secrets.token_bytes(32)
            
            # Enroll PUF challenge (generates stable key + helper data)
            stable_key, helper_data = puf.enroll_challenge(challenge)
            
            # Generate RLWE keypair
            public_key, private_key = self.rlwe.generate_keypair()
            
            # Encrypt PUF stable key using RLWE
            key_poly = bytes_to_poly(stable_key, self.n)
            encrypted_response = []
            
            # Encrypt each bit of the stable key (only encrypt actual key length)
            key_length = len(stable_key)
            for coeff in key_poly[:key_length]:  # Use actual stable key length
                for bit in range(8):
                    bit_val = (coeff >> bit) & 1
                    ct = self.rlwe.encrypt(public_key, bit_val)
                    encrypted_response.append(ct)
            
            crps.append({
                'challenge': challenge.hex(),
                'helper_data': helper_data.hex(),  # Store helper data
                'public_key': (public_key[0].tolist(), public_key[1].tolist()),
                'private_key': private_key.tolist(),
                'encrypted_response': [(u.tolist(), v.tolist()) for u, v in encrypted_response]
            })
        
        enrollment_data = {
            'device_id': device_id,
            'crps': crps,
            'timestamp': secrets.token_hex(16)
        }
        
        elapsed = time.time() - start_time
        self.metrics.record('enrollment', elapsed, data_size=len(json.dumps(enrollment_data)))
        
        return enrollment_data
    
    def generate_auth_challenge(self, enrollment_data: Dict) -> Tuple[bytes, int]:
        """
        Generate authentication challenge for a device.
        
        Returns: (challenge, crp_index)
        """
        # Select a random CRP
        crp_index = secrets.randbelow(len(enrollment_data['crps']))
        challenge_hex = enrollment_data['crps'][crp_index]['challenge']
        challenge = bytes.fromhex(challenge_hex)
        
        return challenge, crp_index
    
    def create_auth_response(self, puf: PUF, challenge: bytes, 
                            nonce: bytes, helper_data: bytes) -> Dict:
        """
        Create authentication response from device side.
        
        Args:
            puf: Device's PUF
            challenge: Challenge from server
            nonce: Fresh nonce for replay protection
            helper_data: Helper data from enrollment for fuzzy extraction
            
        Returns: Authentication response data
        """
        start_time = time.time()
        
        # Reproduce stable key from noisy PUF response using fuzzy extractor
        puf_response = puf.authenticate_challenge(challenge, helper_data)
        
        if puf_response is None:
            # Fallback: try without noise tolerance
            puf_response = puf.get_stable_response(challenge)
        
        # Generate ephemeral RLWE keypair
        public_key, private_key = self.rlwe.generate_keypair()
        
        # Create authentication token combining PUF response and nonce
        auth_token = hashlib.sha256(puf_response + nonce).digest()
        
        # Encrypt authentication token with RLWE
        enc_start = time.time()
        token_poly = bytes_to_poly(auth_token, self.n)
        encrypted_token = []
        
        for coeff in token_poly[:32]:  # First 32 bytes
            for bit in range(8):
                bit_val = (coeff >> bit) & 1
                ct = self.rlwe.encrypt(public_key, bit_val)
                encrypted_token.append(ct)
        
        enc_elapsed = time.time() - enc_start
        self.metrics.record('encryption', enc_elapsed, data_size=32)
        
        # Sign the response with PUF-derived key
        sig_start = time.time()
        signature = self._sign_response(puf_response, nonce, public_key)
        sig_elapsed = time.time() - sig_start
        self.metrics.record('signature_generation', sig_elapsed)
        
        response = {
            'public_key': (public_key[0].tolist(), public_key[1].tolist()),
            'encrypted_token': [(u.tolist(), v.tolist()) for u, v in encrypted_token],
            'signature': signature.hex(),
            'nonce': nonce.hex()
        }
        
        elapsed = time.time() - start_time
        self.metrics.record('authentication', elapsed, data_size=len(json.dumps(response)))
        
        return response
    
    def verify_auth_response(self, enrollment_data: Dict, crp_index: int,
                            challenge: bytes, response: Dict, nonce: bytes) -> bool:
        """
        Verify authentication response from device.
        
        Args:
            enrollment_data: Stored enrollment data
            crp_index: Index of CRP used
            challenge: Challenge sent to device
            response: Response from device
            nonce: Nonce used in challenge
            
        Returns: True if authentication successful
        """
        start_time = time.time()
        
        try:
            # Get enrolled CRP
            crp = enrollment_data['crps'][crp_index]
            
            # Decrypt the enrolled PUF stable key
            dec_start = time.time()
            private_key = np.array(crp['private_key'], dtype=np.int64)
            enrolled_stable_key = self._decrypt_puf_response(
                crp['encrypted_response'], private_key
            )
            dec_elapsed = time.time() - dec_start
            self.metrics.record('decryption', dec_elapsed, data_size=len(enrolled_stable_key))
            
            # Compute expected authentication token
            expected_token = hashlib.sha256(enrolled_stable_key + nonce).digest()
            
            # Decrypt received encrypted token
            response_public_key = (
                np.array(response['public_key'][0], dtype=np.int64),
                np.array(response['public_key'][1], dtype=np.int64)
            )
            
            # Verify signature
            sig_start = time.time()
            signature = bytes.fromhex(response['signature'])
            verify_result = self._verify_signature(enrolled_stable_key, nonce, 
                                         response_public_key, signature)
            sig_elapsed = time.time() - sig_start
            self.metrics.record('signature_verification', sig_elapsed)
            
            if not verify_result:
                return False
            
            # Additional verification: check nonce freshness
            if response['nonce'] != nonce.hex():
                return False
            
            elapsed = time.time() - start_time
            print(f"[PERF] Authentication verification: {elapsed*1000:.2f}ms")
            
            return True
            
        except Exception as e:
            print(f"[AUTH DEBUG] Verification error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _decrypt_puf_response(self, encrypted_response: list, 
                             private_key: np.ndarray) -> bytes:
        """Decrypt PUF response from encrypted format."""
        decrypted_bits = []
        
        for ct_list in encrypted_response:
            u = np.array(ct_list[0], dtype=np.int64)
            v = np.array(ct_list[1], dtype=np.int64)
            bit = self.rlwe.decrypt(private_key, (u, v))
            decrypted_bits.append(bit)
        
        # Convert bits to bytes
        decrypted_bytes = []
        for i in range(0, len(decrypted_bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(decrypted_bits):
                    byte_val |= (decrypted_bits[i + j] << j)
            decrypted_bytes.append(byte_val)
        
        return bytes(decrypted_bytes)
    
    def _sign_response(self, puf_response: bytes, nonce: bytes,
                      public_key: Tuple[np.ndarray, np.ndarray]) -> bytes:
        """Create signature for authentication response."""
        # Derive signing key from PUF response
        signing_key = hashlib.sha256(puf_response + b"signing_key").digest()
        
        # Create message to sign
        pk_bytes = public_key[0].tobytes() + public_key[1].tobytes()
        message = nonce + pk_bytes
        
        # Sign with HMAC
        signature = hashlib.sha256(signing_key + message).digest()
        return signature
    
    def _verify_signature(self, puf_response: bytes, nonce: bytes,
                         public_key: Tuple[np.ndarray, np.ndarray],
                         signature: bytes) -> bool:
        """Verify signature on authentication response."""
        # Derive signing key from PUF response
        signing_key = hashlib.sha256(puf_response + b"signing_key").digest()
        
        # Recreate message
        pk_bytes = public_key[0].tobytes() + public_key[1].tobytes()
        message = nonce + pk_bytes
        
        # Verify signature
        expected_signature = hashlib.sha256(signing_key + message).digest()
        return secrets.compare_digest(signature, expected_signature)


class SessionManager:
    """Manage authenticated sessions with forward secrecy."""
    
    def __init__(self):
        self.sessions = {}
        
    def create_session(self, device_id: str, rlwe: RLWE) -> Tuple[str, Dict]:
        """
        Create new session with ephemeral keys.
        
        Returns: (session_id, session_data)
        """
        session_id = secrets.token_hex(32)
        
        # Generate session keypair
        public_key, private_key = rlwe.generate_keypair()
        
        session_data = {
            'device_id': device_id,
            'session_key': secrets.token_bytes(32),
            'public_key': public_key,
            'private_key': private_key,
            'timestamp': secrets.token_hex(16)
        }
        
        self.sessions[session_id] = session_data
        return session_id, session_data
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve session data."""
        return self.sessions.get(session_id)
    
    def close_session(self, session_id: str):
        """Close and remove session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def encrypt_message(self, session_id: str, message: bytes, 
                       rlwe: RLWE) -> Optional[list]:
        """Encrypt message using session key."""
        session = self.get_session(session_id)
        if not session:
            return None
        
        # XOR message with session key for symmetric encryption
        session_key = session['session_key']
        encrypted = bytes(m ^ session_key[i % len(session_key)] 
                         for i, m in enumerate(message))
        
        # Additional layer with RLWE
        public_key = session['public_key']
        encrypted_poly = bytes_to_poly(encrypted, rlwe.n)
        
        rlwe_encrypted = []
        for coeff in encrypted_poly[:min(32, len(encrypted))]:
            for bit in range(8):
                bit_val = (coeff >> bit) & 1
                ct = rlwe.encrypt(public_key, bit_val)
                rlwe_encrypted.append((ct[0].tolist(), ct[1].tolist()))
        
        return rlwe_encrypted
    
    def decrypt_message(self, session_id: str, encrypted: list,
                       rlwe: RLWE) -> Optional[bytes]:
        """Decrypt message using session key."""
        session = self.get_session(session_id)
        if not session:
            return None
        
        # Decrypt RLWE layer
        private_key = session['private_key']
        decrypted_bits = []
        
        for ct_list in encrypted:
            u = np.array(ct_list[0], dtype=np.int64)
            v = np.array(ct_list[1], dtype=np.int64)
            bit = rlwe.decrypt(private_key, (u, v))
            decrypted_bits.append(bit)
        
        # Convert bits to bytes
        decrypted_bytes = []
        for i in range(0, len(decrypted_bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(decrypted_bits):
                    byte_val |= (decrypted_bits[i + j] << j)
            decrypted_bytes.append(byte_val)
        
        intermediate = bytes(decrypted_bytes)
        
        # Decrypt session key layer
        session_key = session['session_key']
        message = bytes(m ^ session_key[i % len(session_key)]
                       for i, m in enumerate(intermediate))
        
        return message
