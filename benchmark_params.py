#!/usr/bin/env python3
"""
Parameter comparison benchmark for PUF-RLWE authentication system.
Tests different RLWE parameter sets: n ∈ {256, 1024}, q ∈ {4096, 7681, 12289, 2^32}
"""

import time
import secrets
import numpy as np
from crypto_utils import PUF, RLWE
from authentication import PUF_RLWE_Authenticator


def benchmark_rlwe_params(n, q, num_iterations=20):
    """
    Benchmark RLWE operations with specific parameters.
    
    Args:
        n: Polynomial degree
        q: Modulus
        num_iterations: Number of iterations for timing
    
    Returns:
        dict with timing results
    """
    print(f"\nTesting n={n}, q={q}")
    print("-" * 50)
    
    try:
        rlwe = RLWE(n=n, q=q)
        
        # Key Generation
        keygen_times = []
        for _ in range(num_iterations):
            start = time.time()
            pk, sk = rlwe.generate_keypair()
            keygen_times.append((time.time() - start) * 1000)  # Convert to ms
        
        # Encryption (256-bit message like in authentication)
        enc_times = []
        ciphertexts = []
        for _ in range(num_iterations):
            start = time.time()
            # Encrypt a 256-bit message (one bit at a time in current implementation)
            cts = []
            for bit_idx in range(256):
                ct = rlwe.encrypt(pk, 1)
                cts.append(ct)
            enc_times.append((time.time() - start) * 1000)
            ciphertexts.append(cts)
        
        # Decryption (128-bit message like in enrollment)
        dec_times = []
        for cts in ciphertexts[:num_iterations]:
            start = time.time()
            # Decrypt 128 bits
            for bit_idx in range(128):
                decrypted = rlwe.decrypt(sk, cts[bit_idx])
            dec_times.append((time.time() - start) * 1000)
        
        # Polynomial Multiplication (core operation)
        polymul_times = []
        for _ in range(num_iterations):
            a = np.random.randint(0, q, n)
            b = np.random.randint(0, q, n)
            start = time.time()
            c = rlwe.poly_mult_enhanced(a, b)
            polymul_times.append((time.time() - start) * 1000)
        
        results = {
            'n': n,
            'q': q,
            'keygen_avg': np.mean(keygen_times),
            'keygen_std': np.std(keygen_times),
            'encrypt_avg': np.mean(enc_times),
            'encrypt_std': np.std(enc_times),
            'decrypt_avg': np.mean(dec_times),
            'decrypt_std': np.std(dec_times),
            'polymul_avg': np.mean(polymul_times),
            'polymul_std': np.std(polymul_times),
            'success': True
        }
        
        print(f"  Key Generation: {results['keygen_avg']:.3f} ± {results['keygen_std']:.3f} ms")
        print(f"  Encryption (256-bit): {results['encrypt_avg']:.3f} ± {results['encrypt_std']:.3f} ms")
        print(f"  Decryption (128-bit): {results['decrypt_avg']:.3f} ± {results['decrypt_std']:.3f} ms")
        print(f"  Poly Multiplication: {results['polymul_avg']:.6f} ± {results['polymul_std']:.6f} ms")
        
        return results
        
    except Exception as e:
        print(f"  ERROR: {str(e)}")
        return {
            'n': n,
            'q': q,
            'success': False,
            'error': str(e)
        }


def benchmark_authentication_params(n, q, num_auths=10):
    """
    Benchmark full authentication with specific RLWE parameters.
    
    Args:
        n: Polynomial degree
        q: Modulus
        num_auths: Number of authentication attempts
    
    Returns:
        dict with timing and success rate
    """
    print(f"\nAuthentication Test: n={n}, q={q}")
    print("-" * 50)
    
    try:
        # Create authenticator with custom RLWE params
        authenticator = PUF_RLWE_Authenticator(n=n, q=q)
        
        # Setup: Enroll device
        puf = PUF()
        device_id = "test_device"
        
        enroll_start = time.time()
        enrollment_data = authenticator.enrollment(puf, device_id)
        enroll_time = (time.time() - enroll_start) * 1000
        
        # Authentication attempts
        client_times = []
        server_times = []
        successful = 0
        
        for i in range(num_auths):
            # Generate challenge
            challenge, crp_index = authenticator.generate_auth_challenge(enrollment_data)
            nonce = secrets.token_bytes(32)
            helper_data_hex = enrollment_data['crps'][crp_index].get('helper_data', '')
            helper_data = bytes.fromhex(helper_data_hex) if helper_data_hex else b''
            
            # Client: Create response
            client_start = time.time()
            auth_response = authenticator.create_auth_response(puf, challenge, nonce, helper_data)
            client_time = (time.time() - client_start) * 1000
            client_times.append(client_time)
            
            # Server: Verify response
            server_start = time.time()
            verified = authenticator.verify_auth_response(
                enrollment_data, crp_index, challenge, auth_response, nonce
            )
            server_time = (time.time() - server_start) * 1000
            server_times.append(server_time)
            
            if verified:
                successful += 1
        
        success_rate = (successful / num_auths) * 100
        
        results = {
            'n': n,
            'q': q,
            'enrollment_time': enroll_time,
            'client_avg': np.mean(client_times),
            'client_std': np.std(client_times),
            'server_avg': np.mean(server_times),
            'server_std': np.std(server_times),
            'success_rate': success_rate,
            'successful': successful,
            'total': num_auths,
            'success': True
        }
        
        print(f"  Enrollment: {results['enrollment_time']:.3f} ms")
        print(f"  Client (Device): {results['client_avg']:.3f} ± {results['client_std']:.3f} ms")
        print(f"  Server: {results['server_avg']:.3f} ± {results['server_std']:.3f} ms")
        print(f"  Success Rate: {success_rate:.1f}% ({successful}/{num_auths})")
        
        return results
        
    except Exception as e:
        print(f"  ERROR: {str(e)}")
        return {
            'n': n,
            'q': q,
            'success': False,
            'error': str(e)
        }


def print_comparison_table(results):
    """Print results in a formatted table."""
    print("\n" + "="*80)
    print("PARAMETER COMPARISON TABLE")
    print("="*80)
    print(f"{'n':<6} {'q':<12} {'Encrypt(ms)':<14} {'Decrypt(ms)':<14} {'Client(ms)':<14} {'Server(ms)':<14} {'Success':<8}")
    print("-"*80)
    
    for result in results:
        if result.get('success', False):
            n = result['n']
            q_str = f"2^32" if result['q'] == 2**32 else str(result['q'])
            enc = result.get('encrypt_avg', 0)
            dec = result.get('decrypt_avg', 0)
            client = result.get('client_avg', 0)
            server = result.get('server_avg', 0)
            success = result.get('success_rate', 0)
            
            print(f"{n:<6} {q_str:<12} {enc:<14.2f} {dec:<14.2f} {client:<14.2f} {server:<14.2f} {success:<8.1f}%")
        else:
            n = result['n']
            q_str = f"2^32" if result['q'] == 2**32 else str(result['q'])
            print(f"{n:<6} {q_str:<12} {'FAILED':<14} {'FAILED':<14} {'FAILED':<14} {'FAILED':<14} {'N/A':<8}")
    
    print("="*80)


def main():
    """Run parameter comparison benchmarks."""
    print("\n" + "="*80)
    print("PUF-RLWE PARAMETER COMPARISON BENCHMARK")
    print("="*80)
    print("\nTesting parameter sets from comparison table:")
    print("  n ∈ {256, 1024}")
    print("  q ∈ {4096, 7681, 12289, 2^32}")
    print("="*80)
    
    # Define parameter sets to test
    params = [
        # n=256 variants
        (256, 4096),
        (256, 7681),      # Current implementation
        (256, 12289),
        (256, 2**32),
        
        # n=1024 variants
        (1024, 4096),
        (1024, 7681),
        (1024, 12289),
        (1024, 2**32),
    ]
    
    all_results = []
    
    # Part 1: RLWE primitive benchmarks
    print("\n" + "="*80)
    print("PART 1: RLWE PRIMITIVE OPERATIONS")
    print("="*80)
    
    for n, q in params:
        result = benchmark_rlwe_params(n, q, num_iterations=20)
        all_results.append(result)
    
    # Part 2: Full authentication benchmarks
    print("\n" + "="*80)
    print("PART 2: FULL AUTHENTICATION PROTOCOL")
    print("="*80)
    
    auth_results = []
    for n, q in params:
        result = benchmark_authentication_params(n, q, num_auths=10)
        # Merge with RLWE results
        for i, r in enumerate(all_results):
            if r['n'] == n and r['q'] == q:
                all_results[i].update(result)
                break
        auth_results.append(result)
    
    # Print summary table
    print_comparison_table(all_results)
    
    # Print recommendations
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    print("\nSecurity vs Performance Trade-offs:")
    print("  • n=256, q=7681:   Current implementation - balanced security/performance")
    print("  • n=256, q=12289:  Higher security, moderate performance impact")
    print("  • n=1024, q=12289: High security, significant performance cost")
    print("  • n=1024, q=2^32:  Maximum security, highest computational cost")
    print("\nNote: Larger n and q provide stronger security against lattice attacks")
    print("      but require more computation time and memory.")
    print("="*80)


if __name__ == "__main__":
    main()
