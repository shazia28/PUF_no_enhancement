#!/usr/bin/env python3
"""
Performance benchmark for PUF-RLWE authentication system.
"""

import time
import secrets
from crypto_utils import PUF, RLWE
from authentication import PUF_RLWE_Authenticator


def benchmark_enrollment(num_devices=10):
    """Benchmark enrollment phase."""
    print(f"\n{'='*60}")
    print(f"ENROLLMENT BENCHMARK ({num_devices} devices)")
    print(f"{'='*60}")
    
    authenticator = PUF_RLWE_Authenticator()
    
    start_time = time.time()
    
    for i in range(num_devices):
        puf = PUF()
        device_id = f"device_{i:03d}"
        enrollment_data = authenticator.enrollment(puf, device_id)
        
        if (i + 1) % 5 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            print(f"  Enrolled {i+1}/{num_devices} devices ({rate:.2f} devices/sec)")
    
    total_time = time.time() - start_time
    avg_time = total_time / num_devices
    
    print(f"\nResults:")
    print(f"  Total Time:    {total_time:.3f}s")
    print(f"  Avg per Device: {avg_time*1000:.2f}ms")
    print(f"  Throughput:     {num_devices/total_time:.2f} devices/sec")
    
    return authenticator


def benchmark_authentication(authenticator, num_auths=50):
    """Benchmark authentication phase."""
    print(f"\n{'='*60}")
    print(f"AUTHENTICATION BENCHMARK ({num_auths} authentications)")
    print(f"{'='*60}")
    
    # Setup: Create one enrolled device
    puf = PUF()
    device_id = "benchmark_device"
    enrollment_data = authenticator.enrollment(puf, device_id)
    
    successful = 0
    start_time = time.time()
    
    for i in range(num_auths):
        # Generate challenge
        challenge, crp_index = authenticator.generate_auth_challenge(enrollment_data)
        nonce = secrets.token_bytes(32)
        helper_data_hex = enrollment_data['crps'][crp_index].get('helper_data', '')
        helper_data = bytes.fromhex(helper_data_hex) if helper_data_hex else b''
        
        # Create response
        auth_response = authenticator.create_auth_response(puf, challenge, nonce, helper_data)
        
        # Verify response
        verified = authenticator.verify_auth_response(
            enrollment_data, crp_index, challenge, auth_response, nonce
        )
        
        if verified:
            successful += 1
        
        if (i + 1) % 10 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            print(f"  Completed {i+1}/{num_auths} authentications ({rate:.2f} auths/sec)")
    
    total_time = time.time() - start_time
    avg_time = total_time / num_auths
    success_rate = (successful / num_auths) * 100
    
    print(f"\nResults:")
    print(f"  Total Time:     {total_time:.3f}s")
    print(f"  Avg per Auth:   {avg_time*1000:.2f}ms")
    print(f"  Throughput:     {num_auths/total_time:.2f} auths/sec")
    print(f"  Success Rate:   {success_rate:.1f}% ({successful}/{num_auths})")


def benchmark_encryption_decryption(num_messages=100):
    """Benchmark RLWE encryption/decryption."""
    print(f"\n{'='*60}")
    print(f"RLWE ENCRYPTION/DECRYPTION BENCHMARK ({num_messages} messages)")
    print(f"{'='*60}")
    
    rlwe = RLWE(n=256, q=7681)
    public_key, private_key = rlwe.generate_keypair()
    
    # Encryption
    enc_start = time.time()
    ciphertexts = []
    for i in range(num_messages):
        plaintext = i % 2  # Alternate 0 and 1
        ct = rlwe.encrypt(public_key, plaintext)
        ciphertexts.append((ct, plaintext))
    enc_time = time.time() - enc_start
    
    # Decryption
    dec_start = time.time()
    correct = 0
    for ct, expected in ciphertexts:
        decrypted = rlwe.decrypt(private_key, ct)
        if decrypted == expected:
            correct += 1
    dec_time = time.time() - dec_start
    
    print(f"\nEncryption:")
    print(f"  Total Time:   {enc_time:.3f}s")
    print(f"  Avg per Msg:  {(enc_time/num_messages)*1000:.2f}ms")
    print(f"  Throughput:   {num_messages/enc_time:.2f} msgs/sec")
    
    print(f"\nDecryption:")
    print(f"  Total Time:   {dec_time:.3f}s")
    print(f"  Avg per Msg:  {(dec_time/num_messages)*1000:.2f}ms")
    print(f"  Throughput:   {num_messages/dec_time:.2f} msgs/sec")
    print(f"  Accuracy:     {(correct/num_messages)*100:.1f}% ({correct}/{num_messages})")


def benchmark_puf_response(num_responses=1000):
    """Benchmark PUF response generation."""
    print(f"\n{'='*60}")
    print(f"PUF RESPONSE BENCHMARK ({num_responses} responses)")
    print(f"{'='*60}")
    
    puf = PUF()
    challenges = [secrets.token_bytes(32) for _ in range(num_responses)]
    
    # Without noise
    start_time = time.time()
    for challenge in challenges:
        response = puf.challenge_response(challenge, add_noise=False)
    no_noise_time = time.time() - start_time
    
    # With noise
    start_time = time.time()
    for challenge in challenges:
        response = puf.challenge_response(challenge, add_noise=True)
    noise_time = time.time() - start_time
    
    print(f"\nWithout Noise:")
    print(f"  Total Time:   {no_noise_time:.3f}s")
    print(f"  Avg per Resp: {(no_noise_time/num_responses)*1000:.3f}ms")
    print(f"  Throughput:   {num_responses/no_noise_time:.2f} resp/sec")
    
    print(f"\nWith Noise (5% flip rate):")
    print(f"  Total Time:   {noise_time:.3f}s")
    print(f"  Avg per Resp: {(noise_time/num_responses)*1000:.3f}ms")
    print(f"  Throughput:   {num_responses/noise_time:.2f} resp/sec")


def benchmark_fuzzy_extractor(num_operations=100):
    """Benchmark fuzzy extractor operations."""
    print(f"\n{'='*60}")
    print(f"FUZZY EXTRACTOR BENCHMARK ({num_operations} operations)")
    print(f"{'='*60}")
    
    puf = PUF()
    challenge = secrets.token_bytes(32)
    
    # Enrollment (generate)
    enroll_start = time.time()
    enrollments = []
    for i in range(num_operations):
        stable_key, helper_data = puf.enroll_challenge(challenge)
        enrollments.append((stable_key, helper_data))
    enroll_time = time.time() - enroll_start
    
    # Authentication (reproduce)
    auth_start = time.time()
    successful = 0
    for stable_key, helper_data in enrollments:
        reproduced = puf.authenticate_challenge(challenge, helper_data)
        if reproduced == stable_key:
            successful += 1
    auth_time = time.time() - auth_start
    
    print(f"\nEnrollment (Generate):")
    print(f"  Total Time:   {enroll_time:.3f}s")
    print(f"  Avg per Op:   {(enroll_time/num_operations)*1000:.2f}ms")
    print(f"  Throughput:   {num_operations/enroll_time:.2f} ops/sec")
    
    print(f"\nAuthentication (Reproduce):")
    print(f"  Total Time:   {auth_time:.3f}s")
    print(f"  Avg per Op:   {(auth_time/num_operations)*1000:.2f}ms")
    print(f"  Throughput:   {num_operations/auth_time:.2f} ops/sec")
    print(f"  Success Rate: {(successful/num_operations)*100:.1f}% ({successful}/{num_operations})")


def main():
    """Run all benchmarks."""
    print("\n" + "="*60)
    print("PUF-RLWE AUTHENTICATION SYSTEM - PERFORMANCE BENCHMARK")
    print("="*60)
    
    # Run benchmarks
    benchmark_puf_response(num_responses=500)
    benchmark_fuzzy_extractor(num_operations=50)
    benchmark_encryption_decryption(num_messages=100)
    
    authenticator = benchmark_enrollment(num_devices=10)
    benchmark_authentication(authenticator, num_auths=20)
    
    # Print detailed metrics
    print("\n" + "="*60)
    print("DETAILED METRICS FROM AUTHENTICATOR")
    print("="*60)
    authenticator.metrics.print_summary()
    
    print("\n" + "="*60)
    print("BENCHMARK COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
