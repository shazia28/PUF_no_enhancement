# PUF-RLWE Authentication System

A secure client-server authentication system combining **Physically Unclonable Functions (PUF)**, **Ring Learning With Errors (RLWE)** cryptography, and **enhanced polynomial multiplication** for IoT device authentication.

## Features

### Core Components

1. **PUF Simulation (`crypto_utils.py`)**
   - Simulates hardware PUF with challenge-response pairs
   - Deterministic but unpredictable responses
   - Noise simulation for realistic behavior

2. **RLWE Cryptography (`crypto_utils.py`)**
   - Post-quantum secure encryption
   - Ring-LWE key generation and encryption/decryption
   - Polynomial operations in quotient ring R_q = Z_q[x]/(x^n + 1)

3. **Enhanced Polynomial Multiplication (`crypto_utils.py`)**
   - **FFT-based multiplication** for efficiency
   - **Karatsuba algorithm** for reduced complexity O(n^log2(3))
   - **Number Theoretic Transform (NTT)** implementation
   - Negacyclic convolution for Ring-LWE operations

4. **Novel Authentication Protocol (`authentication.py`)**
   - **Enrollment Phase**: Device registers PUF responses encrypted with RLWE
   - **Challenge-Response Authentication**: Server challenges device, receives PUF-RLWE proof
   - **Session Management**: Secure sessions with forward secrecy
   - **Signature Verification**: PUF-derived signatures for response authentication

### Security Features

- **Post-quantum resistance** through RLWE
- **Hardware-binding** via PUF
- **Forward secrecy** with ephemeral keys
- **Replay protection** using nonces
- **Encrypted communication** with session keys

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### Starting the Server

```bash
python server.py
```

The server will:
- Listen on port 8888 (configurable)
- Handle device enrollment
- Authenticate devices using PUF-RLWE protocol
- Manage secure communication sessions

### Running the Client

**Interactive Mode:**
```bash
python client.py
# Select option 1 for interactive mode
```

**Demo Mode:**
```bash
python client.py
# Select option 2 for automated demo
```

### Client Operations

1. **Enroll Device**
   - Generate PUF challenge-response pairs
   - Encrypt responses with RLWE
   - Register with server

2. **Authenticate**
   - Receive challenge from server
   - Generate PUF response
   - Create signed authentication proof
   - Establish secure session

3. **Send Secure Messages**
   - Encrypt messages with session keys and RLWE
   - Send encrypted data
   - Receive encrypted responses

## Architecture

### Authentication Flow

```
Client                          Server
  |                               |
  |---(1) Enrollment Data-------->|
  |<--(2) Enrollment Confirm------|
  |                               |
  |---(3) Auth Request----------->|
  |<--(4) Challenge + Nonce-------|
  |                               |
  |---(5) PUF Response + Sig----->|
  |<--(6) Session Established-----|
  |                               |
  |---(7) Encrypted Message------>|
  |<--(8) Encrypted Response------|
```

### Protocol Details

**Enrollment:**
- Client generates multiple CRPs using PUF
- Each PUF response is encrypted with RLWE public key
- Encrypted data stored on server
- Private keys kept only on device

**Authentication:**
- Server selects random CRP and generates nonce
- Client computes PUF response and creates authentication token
- Token = SHA256(PUF_response || nonce)
- Token encrypted with ephemeral RLWE key
- Signature computed using PUF-derived key

**Secure Communication:**
- Session established with shared session key
- Messages encrypted with session key + RLWE layer
- Double encryption for defense in depth

## Technical Specifications

### RLWE Parameters
- **Polynomial degree (n)**: 256
- **Modulus (q)**: 7681
- **Error distribution (σ)**: 3.2
- **Ring**: Z_q[x]/(x^n + 1)

### PUF Configuration
- **Challenge size**: 256 bits
- **Response size**: 256 bits
- **Number of CRPs**: 10 per device
- **Noise simulation**: Gaussian distribution

### Polynomial Multiplication Methods
1. **Standard schoolbook**: O(n²) - baseline
2. **Karatsuba**: O(n^1.585) - recursive optimization
3. **FFT/NTT**: O(n log n) - frequency domain multiplication

## File Structure

```
PUF_no_enhancement/
├── crypto_utils.py       # PUF, RLWE, polynomial multiplication
├── authentication.py     # Authentication protocol and session management
├── server.py            # Server implementation
├── client.py            # Client implementation
├── requirements.txt     # Python dependencies
├── config.json         # Configuration parameters
└── README.md           # This file
```

## Security Considerations

### Strengths
- **Post-quantum security**: RLWE is resistant to quantum attacks
- **Physical security**: PUF binds cryptographic keys to hardware
- **No shared secrets**: Each device has unique PUF characteristics
- **Forward secrecy**: Ephemeral keys for each session
- **Replay protection**: Nonces prevent replay attacks

### Limitations
- PUF simulation (hardware PUF recommended for production)
- Simplified error correction (fuzzy extractors needed for real PUF)
- Network security not implemented (use TLS/SSL in production)
- No certificate validation (add PKI for production)

## Advanced Features

### Enhanced Polynomial Multiplication

The system implements three multiplication algorithms:

1. **FFT-based (Default for RLWE)**:
   ```python
   result = rlwe.poly_mult_enhanced(a, b)
   ```
   - Uses Fast Fourier Transform
   - O(n log n) complexity
   - Suitable for large polynomials

2. **Karatsuba Algorithm**:
   ```python
   result = EnhancedPolyMultiplier.karatsuba_mult(a, b, q)
   ```
   - Divide-and-conquer approach
   - O(n^1.585) complexity
   - Better for medium-sized polynomials

3. **NTT (Number Theoretic Transform)**:
   ```python
   result = EnhancedPolyMultiplier.ntt_mult(a, b, q, n)
   ```
   - Exact integer arithmetic
   - Optimal for Ring-LWE when parameters support it

## Configuration

Edit `config.json` to customize:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8888
    },
    "rlwe_parameters": {
        "n": 256,
        "q": 7681,
        "sigma": 3.2
    }
}
```

## Testing

Run a complete test:

1. Start server in one terminal:
   ```bash
   python server.py
   ```

2. Run demo client in another terminal:
   ```bash
   python client.py
   # Select option 2 (Demo mode)
   ```

This will automatically:
- Enroll a device
- Authenticate the device
- Send encrypted messages
- Verify secure communication

## Future Enhancements

- Hardware PUF integration
- Fuzzy extractors for error correction
- Multi-party authentication
- Blockchain integration for audit trails
- TLS/SSL transport layer security
- Certificate-based PKI
- Rate limiting and DoS protection
- Database persistence for enrollment data

## References

- Ring-LWE: Lyubashevsky, V., Peikert, C., & Regev, O. (2010)
- PUF: Gassend, B., et al. (2002)
- NTT: Longa, P., & Naehrig, M. (2016)

## License

This is an educational implementation for research purposes.

## Author

Implementation demonstrating PUF + RLWE + Enhanced Polynomial Multiplication authentication.