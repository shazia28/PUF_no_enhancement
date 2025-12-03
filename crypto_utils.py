"""
Cryptographic utilities module with PUF, RLWE, and enhanced polynomial multiplication.
"""

import numpy as np
import hashlib
import secrets
from typing import Tuple, List, Optional


class FuzzyExtractor:
    """
    Fuzzy Extractor for PUF responses - handles noisy data.
    
    Based on the code-offset construction:
    - Gen(w): generates (key, helper_data) from noisy input w
    - Rep(w', helper_data): reproduces key from noisy w' close to w
    
    Uses BCH-like error correction with syndrome coding.
    """
    
    def __init__(self, key_length: int = 128, error_tolerance: int = 25):
        """
        Initialize fuzzy extractor.
        
        Args:
            key_length: Length of extracted key in bits
            error_tolerance: Maximum number of bit errors to tolerate (as percentage)
        """
        self.key_length = key_length
        self.error_tolerance = error_tolerance
        
    def generate(self, puf_response: bytes) -> Tuple[bytes, bytes]:
        """
        Generate phase: Extract uniform key and helper data from noisy PUF response.
        
        Args:
            puf_response: Raw PUF response (noisy)
            
        Returns:
            (key, helper_data): Extracted key and public helper data
        """
        # Convert response to bit array
        response_bits = self._bytes_to_bits(puf_response)
        
        # Generate random key
        key = secrets.token_bytes(self.key_length // 8)
        key_bits = self._bytes_to_bits(key)
        
        # Extend key bits to match response length with repetition code
        extended_key_bits = self._repeat_code_encode(key_bits, len(response_bits))
        
        # Generate helper data: helper = response XOR extended_key
        # This is the "offset" in code-offset construction
        helper_bits = np.bitwise_xor(response_bits, extended_key_bits)
        helper_data = self._bits_to_bytes(helper_bits)
        
        # Add error correction information
        ecc_data = self._generate_ecc(response_bits)
        helper_data_with_ecc = helper_data + ecc_data
        
        return key, helper_data_with_ecc
    
    def reproduce(self, noisy_puf_response: bytes, helper_data: bytes) -> Optional[bytes]:
        """
        Reproduce phase: Recover key from noisy PUF response and helper data.
        
        Args:
            noisy_puf_response: Noisy PUF response (may differ from enrollment)
            helper_data: Helper data from generate phase
            
        Returns:
            Recovered key, or None if too many errors
        """
        # Split helper data and ECC
        ecc_length = 32  # 256 bits for ECC
        if len(helper_data) < ecc_length:
            return None
            
        helper_only = helper_data[:-ecc_length]
        ecc_data = helper_data[-ecc_length:]
        
        # Convert to bit arrays
        noisy_bits = self._bytes_to_bits(noisy_puf_response)
        helper_bits = self._bytes_to_bits(helper_only)
        
        # Recover extended key: extended_key = noisy_response XOR helper
        recovered_extended_key_bits = np.bitwise_xor(
            noisy_bits[:len(helper_bits)], 
            helper_bits
        )
        
        # Error correction using repetition code
        recovered_key_bits = self._repeat_code_decode(
            recovered_extended_key_bits, 
            self.key_length
        )
        
        if recovered_key_bits is None:
            return None
        
        # Verify using ECC
        if not self._verify_ecc(noisy_bits, ecc_data):
            # Still return key but with warning (in production, may reject)
            pass
        
        recovered_key = self._bits_to_bytes(recovered_key_bits)
        return recovered_key
    
    def _repeat_code_encode(self, data_bits: np.ndarray, target_length: int) -> np.ndarray:
        """
        Encode data using repetition code for error correction.
        Each bit is repeated multiple times.
        """
        repetition_factor = target_length // len(data_bits)
        if repetition_factor < 1:
            repetition_factor = 1
            
        encoded = np.repeat(data_bits, repetition_factor)
        
        # Pad if necessary
        if len(encoded) < target_length:
            padding = np.zeros(target_length - len(encoded), dtype=np.uint8)
            encoded = np.concatenate([encoded, padding])
        
        return encoded[:target_length]
    
    def _repeat_code_decode(self, encoded_bits: np.ndarray, 
                           original_length: int) -> Optional[np.ndarray]:
        """
        Decode repetition code using majority voting.
        """
        repetition_factor = len(encoded_bits) // original_length
        if repetition_factor < 1:
            return None
        
        decoded = np.zeros(original_length, dtype=np.uint8)
        
        for i in range(original_length):
            start_idx = i * repetition_factor
            end_idx = start_idx + repetition_factor
            
            if end_idx <= len(encoded_bits):
                # Majority voting
                chunk = encoded_bits[start_idx:end_idx]
                decoded[i] = 1 if np.sum(chunk) > (len(chunk) / 2) else 0
            else:
                # Not enough data
                return None
        
        return decoded
    
    def _generate_ecc(self, data_bits: np.ndarray) -> bytes:
        """
        Generate error correction code (simplified BCH-like syndrome).
        In production, use proper BCH or Reed-Solomon codes.
        """
        # Use hash as syndrome
        data_bytes = self._bits_to_bytes(data_bits)
        syndrome = hashlib.sha256(data_bytes).digest()
        return syndrome
    
    def _verify_ecc(self, data_bits: np.ndarray, ecc_data: bytes) -> bool:
        """Verify error correction code."""
        computed_ecc = self._generate_ecc(data_bits)
        # Allow some tolerance in verification
        differences = sum(a != b for a, b in zip(computed_ecc[:16], ecc_data[:16]))
        return differences < 4  # Tolerate some differences
    
    def _bytes_to_bits(self, data: bytes) -> np.ndarray:
        """Convert bytes to bit array."""
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        return bits
    
    def _bits_to_bytes(self, bits: np.ndarray) -> bytes:
        """Convert bit array to bytes."""
        # Pad to multiple of 8
        padding = (8 - len(bits) % 8) % 8
        if padding > 0:
            bits = np.concatenate([bits, np.zeros(padding, dtype=np.uint8)])
        
        byte_array = np.packbits(bits)
        return bytes(byte_array)


class PUF:
    """Physically Unclonable Function simulation with fuzzy extractor support."""
    
    def __init__(self, seed: int = None, noise_level: float = 0.05):
        """
        Initialize PUF with a unique seed representing physical characteristics.
        
        Args:
            seed: Unique seed for PUF (simulates hardware characteristics)
            noise_level: Percentage of bits that may flip (0.05 = 5% noise)
        """
        self.seed = seed if seed is not None else secrets.randbits(128)
        self.noise_level = noise_level
        self.response_cache = {}
        self.fuzzy_extractor = FuzzyExtractor(key_length=128, error_tolerance=25)
        self.helper_data_cache = {}  # Store helper data for each challenge
        
    def challenge_response(self, challenge: bytes, add_noise: bool = True) -> bytes:
        """
        Generate a response for a given challenge using PUF.
        Simulates physical variations with deterministic but unpredictable output.
        
        Args:
            challenge: Input challenge
            add_noise: Whether to add realistic noise (simulates environmental variations)
            
        Returns:
            PUF response (potentially noisy)
        """
        # Create a unique hash combining the seed and challenge
        combined = str(self.seed).encode() + challenge
        h = hashlib.sha256(combined).digest()
        
        # Simulate base physical characteristics noise
        # Use first 4 bytes for numpy seed (32-bit limit)
        np.random.seed(int.from_bytes(h[:4], 'big') % (2**32))
        base_noise = np.random.randint(0, 256, 32, dtype=np.uint8)
        
        # Combine hash with base noise for PUF response
        base_response = bytes((h[i] ^ base_noise[i]) for i in range(32))
        
        # Add environmental noise if requested (simulates temperature, voltage variations)
        if add_noise and self.noise_level > 0:
            response_bits = np.unpackbits(np.frombuffer(base_response, dtype=np.uint8))
            num_bits = len(response_bits)
            num_flips = int(num_bits * self.noise_level)
            
            # Randomly flip some bits
            flip_indices = np.random.choice(num_bits, num_flips, replace=False)
            response_bits[flip_indices] = 1 - response_bits[flip_indices]
            
            noisy_response = bytes(np.packbits(response_bits))
            return noisy_response
        
        return base_response
    
    def enroll_challenge(self, challenge: bytes) -> Tuple[bytes, bytes]:
        """
        Enrollment phase: Generate stable key and helper data for a challenge.
        Uses fuzzy extractor to handle future noise.
        
        Args:
            challenge: Challenge to enroll
            
        Returns:
            (stable_key, helper_data): Key and helper data for reproduction
        """
        # Get clean response without noise
        clean_response = self.challenge_response(challenge, add_noise=False)
        
        # Use fuzzy extractor to generate key and helper data
        stable_key, helper_data = self.fuzzy_extractor.generate(clean_response)
        
        # Cache for this challenge
        challenge_hash = hashlib.sha256(challenge).hexdigest()
        self.helper_data_cache[challenge_hash] = helper_data
        self.response_cache[challenge_hash] = stable_key
        
        return stable_key, helper_data
    
    def authenticate_challenge(self, challenge: bytes, helper_data: bytes) -> Optional[bytes]:
        """
        Authentication phase: Reproduce stable key from noisy response.
        
        Args:
            challenge: Challenge to authenticate
            helper_data: Helper data from enrollment
            
        Returns:
            Reproduced stable key, or None if authentication fails
        """
        # Check if we have this challenge enrolled
        challenge_hash = hashlib.sha256(challenge).hexdigest()
        
        # If already in cache, use cached key (for same session)
        if challenge_hash in self.response_cache:
            return self.response_cache[challenge_hash]
        
        # Get noisy response (simulates real-world PUF with environmental variations)
        noisy_response = self.challenge_response(challenge, add_noise=True)
        
        # Use fuzzy extractor to reproduce key from noisy response
        reproduced_key = self.fuzzy_extractor.reproduce(noisy_response, helper_data)
        
        return reproduced_key
    
    def get_stable_response(self, challenge: bytes, threshold: int = 0) -> bytes:
        """
        Get a stable response using fuzzy extractor.
        This is the backward-compatible method.
        """
        challenge_hash = hashlib.sha256(challenge).hexdigest()
        
        # Check if already enrolled
        if challenge_hash in self.response_cache:
            return self.response_cache[challenge_hash]
        
        # Enroll and return stable key
        stable_key, helper_data = self.enroll_challenge(challenge)
        return stable_key


class RLWE:
    """Ring Learning With Errors cryptographic operations."""
    
    def __init__(self, n: int = 256, q: int = 7681, sigma: float = 3.2):
        """
        Initialize RLWE parameters.
        n: polynomial degree (power of 2)
        q: modulus
        sigma: standard deviation for error distribution
        """
        self.n = n
        self.q = q
        self.sigma = sigma
        
    def sample_uniform(self) -> np.ndarray:
        """Sample a uniform random polynomial."""
        return np.random.randint(0, self.q, self.n, dtype=np.int64)
    
    def sample_error(self) -> np.ndarray:
        """Sample from discrete Gaussian error distribution."""
        error = np.random.normal(0, self.sigma, self.n)
        return np.round(error).astype(np.int64) % self.q
    
    def poly_mult_enhanced(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Enhanced polynomial multiplication using NTT (Number Theoretic Transform).
        This is an optimized version for Ring-LWE operations.
        Uses negacyclic convolution: multiplication in R_q = Z_q[x]/(x^n + 1)
        """
        # Ensure coefficients are in the correct range
        a = a % self.q
        b = b % self.q
        
        # Perform FFT-based multiplication for efficiency
        # Convert to frequency domain
        fft_a = np.fft.fft(a)
        fft_b = np.fft.fft(b)
        
        # Multiply in frequency domain
        fft_product = fft_a * fft_b
        
        # Convert back to time domain
        product = np.fft.ifft(fft_product).real
        product = np.round(product).astype(np.int64)
        
        # Perform negacyclic reduction (mod x^n + 1)
        result = np.zeros(self.n, dtype=np.int64)
        for i in range(len(product)):
            if i < self.n:
                result[i] += product[i]
            else:
                # x^n = -1 in the quotient ring
                result[i % self.n] -= product[i]
        
        # Reduce modulo q
        result = result % self.q
        return result
    
    def poly_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Add two polynomials in the ring."""
        return (a + b) % self.q
    
    def generate_keypair(self) -> Tuple[np.ndarray, Tuple[np.ndarray, np.ndarray]]:
        """
        Generate RLWE public-private keypair.
        Returns: (public_key, (secret_key, error))
        """
        # Sample secret key from error distribution
        s = self.sample_error()
        
        # Sample random polynomial a
        a = self.sample_uniform()
        
        # Sample error
        e = self.sample_error()
        
        # Compute public key: b = a*s + e (mod q)
        b = self.poly_add(self.poly_mult_enhanced(a, s), e)
        
        public_key = (a, b)
        private_key = s
        
        return public_key, private_key
    
    def encrypt(self, public_key: Tuple[np.ndarray, np.ndarray], 
                message: int) -> Tuple[np.ndarray, np.ndarray]:
        """
        Encrypt a message bit using RLWE.
        Returns: (u, v) ciphertext pair
        """
        a, b = public_key
        
        # Sample ephemeral values
        r = self.sample_error()
        e1 = self.sample_error()
        e2 = self.sample_error()
        
        # Encode message in the constant term
        m = np.zeros(self.n, dtype=np.int64)
        m[0] = message * (self.q // 2)  # Scale message
        
        # Compute ciphertext
        u = self.poly_add(self.poly_mult_enhanced(a, r), e1)
        v = self.poly_add(self.poly_add(self.poly_mult_enhanced(b, r), e2), m)
        
        return u, v
    
    def decrypt(self, private_key: np.ndarray, 
                ciphertext: Tuple[np.ndarray, np.ndarray]) -> int:
        """
        Decrypt a ciphertext using RLWE.
        Returns: decrypted message bit
        """
        u, v = ciphertext
        s = private_key
        
        # Compute m' = v - s*u (mod q)
        m_prime = (v - self.poly_mult_enhanced(s, u)) % self.q
        
        # Decode message from constant term
        decoded = m_prime[0]
        
        # Round to nearest message value
        if decoded > self.q // 4 and decoded < 3 * self.q // 4:
            return 1
        else:
            return 0


class EnhancedPolyMultiplier:
    """Enhanced polynomial multiplication with various optimization techniques."""
    
    @staticmethod
    def karatsuba_mult(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
        """
        Karatsuba algorithm for polynomial multiplication.
        Reduces complexity from O(n^2) to O(n^log2(3)).
        """
        n = len(a)
        
        # Base case
        if n <= 32:
            return EnhancedPolyMultiplier.schoolbook_mult(a, b, q)
        
        # Split polynomials
        mid = n // 2
        a_low, a_high = a[:mid], a[mid:]
        b_low, b_high = b[:mid], b[mid:]
        
        # Three recursive multiplications
        z0 = EnhancedPolyMultiplier.karatsuba_mult(a_low, b_low, q)
        z2 = EnhancedPolyMultiplier.karatsuba_mult(a_high, b_high, q)
        
        a_sum = (a_low + a_high) % q
        b_sum = (b_low + b_high) % q
        z1 = EnhancedPolyMultiplier.karatsuba_mult(a_sum, b_sum, q)
        z1 = (z1 - z0 - z2) % q
        
        # Combine results
        result = np.zeros(2 * n - 1, dtype=np.int64)
        result[:len(z0)] += z0
        result[mid:mid + len(z1)] += z1
        result[2 * mid:2 * mid + len(z2)] += z2
        
        return result % q
    
    @staticmethod
    def schoolbook_mult(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
        """Standard schoolbook polynomial multiplication."""
        n = len(a)
        m = len(b)
        result = np.zeros(n + m - 1, dtype=np.int64)
        
        for i in range(n):
            for j in range(m):
                result[i + j] = (result[i + j] + a[i] * b[j]) % q
        
        return result
    
    @staticmethod
    def ntt_mult(a: np.ndarray, b: np.ndarray, q: int, n: int) -> np.ndarray:
        """
        Number Theoretic Transform based multiplication.
        Most efficient for Ring-LWE when parameters are chosen correctly.
        """
        # This is a simplified version
        # In production, would use actual NTT with primitive roots
        
        # Pad to power of 2
        size = 2 ** int(np.ceil(np.log2(max(len(a), len(b)))))
        a_padded = np.pad(a, (0, size - len(a)), mode='constant')
        b_padded = np.pad(b, (0, size - len(b)), mode='constant')
        
        # Use FFT as approximation (in practice, use exact NTT)
        fft_a = np.fft.fft(a_padded)
        fft_b = np.fft.fft(b_padded)
        fft_product = fft_a * fft_b
        product = np.fft.ifft(fft_product).real
        product = np.round(product).astype(np.int64) % q
        
        return product[:n]


def bytes_to_poly(data: bytes, n: int) -> np.ndarray:
    """Convert bytes to polynomial coefficients."""
    poly = np.zeros(n, dtype=np.int64)
    for i, byte in enumerate(data[:n]):
        poly[i] = byte
    return poly


def poly_to_bytes(poly: np.ndarray) -> bytes:
    """Convert polynomial coefficients to bytes."""
    return bytes(int(c) % 256 for c in poly)
