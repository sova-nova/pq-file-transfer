# PQ File Transfer

A cross-platform file transfer application with post-quantum cryptographic protection. Files are encrypted client-side using ML-KEM-768 (key exchange), ML-DSA-65 (signatures), AES-256-GCM (encryption), and HKDF-SHA256 (key derivation). The relay server never sees plaintext data.

## Architecture

```mermaid
graph LR
    A[Client A<br/>Sender] -->|encrypted blob| B[Relay Server<br/>blind relay]
    B -->|encrypted blob| C[Client B<br/>Receiver]

- **Client** — Qt 6 desktop application with GUI
- **Relay Server** — Lightweight TCP relay that stores and forwards encrypted blobs
- **Protocol** — Length-prefixed binary messages with chunked transfer

## Cryptographic primitives

| Purpose | Algorithm | Standard |
|---|---|---|
| Key exchange | ML-KEM-768 | FIPS 203 |
| Digital signatures | ML-DSA-65 | FIPS 204 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | RFC 5869 |

### Security properties

- **Confidentiality** — Files are encrypted before leaving the client. The server only sees ciphertext.
- **Authenticity** — File headers are signed with ML-DSA-65. The receiver verifies the sender's identity.
- **Forward secrecy** — Each transfer uses a fresh ML-KEM encapsulation and random nonce.
- **Integrity** — AES-GCM authentication tags detect any tampering of chunk data.

## Dependencies

| Library | Purpose | Version |
|---|---|---|
| Qt 6 | GUI framework | 6.0+ |
| liboqs | ML-KEM-768, ML-DSA-65 | 0.10+ |
| OpenSSL | AES-256-GCM, HKDF-SHA256 | 3.0+ |
| CMake | Build system | 3.16+ |
| C++17 compiler | (GCC 9+, Clang 10+, MSVC 2019+) | |

## Build

### Install dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install cmake build-essential qt6-base-dev libssl-dev

# Build liboqs from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### Fedora

```bash
sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl-devel

# Build liboqs from source (same as Ubuntu above)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### macOS

```bash
brew install cmake qt openssl

# Build liboqs from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOPENSSL_ROOT_DIR=$(brew --prefix openssl) ..
make -j$(nproc)
sudo make install
```

### Compile

```bash
git clone https://github.com/sova-nova/pq-file-transfer.git
cd pq-file-transfer
mkdir build && cd build
cmake ..
make
```

On macOS, if CMake cannot find Qt6:
```bash
cmake -DCMAKE_PREFIX_PATH=$(brew --prefix qt) ..
```

#### Usage
1. Start the relay server

```bash
./pq-server
```

The server listens on port 9000 by default. Files are stored in /tmp/pq-transfer/ and deleted after download.

2. Start the client

```bash
./pq-client
```

On first run, the app generates ML-KEM-768 and ML-DSA-65 keypairs and saves them to ~/.pq-file-transfer/keys/. A fingerprint (first 8 bytes of your DSA public key) is displayed in the GUI.

3. Exchange public keys with your contact

Export your public keys:

```bash
cp ~/.pq-file-transfer/keys/public_kem ~/yourname_pub_kem
cp ~/.pq-file-transfer/keys/public_dsa ~/yourname_pub_dsa
```

Send both files to your contact through any channel (email, USB, etc.). These are public keys — safe to share openly.

Have your contact do the same and send you their keys.

4. Add a contact

    Click the "+" button next to the "Send to:" dropdown
    Enter a name for the contact
    Select their public_kem file
    Select their public_dsa file

5. Send a file

    Select a contact from the dropdown (or "self" for testing)
    Click "Send File"
    Choose a file
    Copy the Transfer ID that appears

6. Receive a file

    Click "Receive File"
    Paste the Transfer ID
    The file is decrypted, verified, and saved to ~/.pq-file-transfer/downloads/
