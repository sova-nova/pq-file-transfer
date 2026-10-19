# PQ File Transfer

A cross-platform file transfer application with post-quantum end-to-end encryption. Files are encrypted on the sender's machine and can only be decrypted by the intended recipient. The relay server in between stores opaque ciphertext and never learns file contents, file names, or who sent a file.

## Architecture

- **Client**: Qt 6 desktop application. It generates keys, manages contacts, encrypts, signs and uploads, and downloads, verifies and decrypts.
- **Relay server**: a small TCP store-and-forward server. It holds encrypted transfers until the recipient fetches them, or for 24 hours at most.
- **Protocol**: length-prefixed binary messages (`[u32 length][u8 type][payload]`) with chunked transfer.

A transfer works like this. The sender uploads and receives a **transfer ID**, then gives that ID to the recipient through any channel. The recipient downloads with the ID, and the server deletes its copy once the recipient confirms the file decrypted and verified correctly.

## Cryptography

| Purpose | Algorithm | Standard |
|---|---|---|
| Key encapsulation | ML-KEM-768 | FIPS 203 |
| Signatures | ML-DSA-65 | FIPS 204 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Fingerprints | SHA-256 of the ML-DSA public key | FIPS 180-4 |

### How a transfer is protected

1. The sender encapsulates to the recipient's ML-KEM public key and gets a fresh shared secret for this transfer.
2. Two AES-256 keys are derived from it, one for file data and one for metadata. The HKDF salt is the SHA-256 hash of the public header (sizes, KEM ciphertext, nonce), so changing any header field breaks decryption.
3. The filename, the sender's fingerprint and an ML-DSA signature are encrypted into a **sealed metadata** block. The signature covers the public header together with the filename and fingerprint.
4. Each chunk is encrypted with AES-GCM. Its nonce is derived from the chunk index, and its associated data includes the index and a last-chunk flag, so chunks can't be reordered, duplicated or dropped without detection.
5. The recipient decapsulates, opens the sealed metadata, and looks up the sender by fingerprint in their contacts. It verifies the signature, then decrypts the chunks into a `.part` file that is renamed only once everything has been authenticated.

### Security properties

- **Confidentiality**: only the holder of the recipient's ML-KEM private key can decrypt.
- **Authenticity**: files are accepted only from senders in your contact list, verified with ML-DSA-65. Unknown senders are rejected.
- **Integrity**: any change to the header or chunks, or any truncation, is detected, and no partial output is kept.
- **Metadata privacy**: the server sees file size, timing and IP addresses, but not file names or sender identity.
- **Per-transfer keys**: each transfer uses a fresh encapsulation, so the keys of one transfer reveal nothing about another.
- **No forward secrecy**: transfers are encrypted to the recipient's long-term key. Anyone who later obtains a recipient's `private_kem` file, together with a stored ciphertext, can decrypt it. Protect your key files.

### Trust model

Security depends on having your contacts' **real** public keys. Public keys can be exchanged over any channel, such as email or chat. When you add a contact, though, the app shows their fingerprint, and you should confirm it with them over a channel where you know you're talking to them, like in person or on a call. If an attacker swaps the key files in transit and you skip this check, the attacker can read the files you send.

Anyone who has a transfer ID can download the ciphertext, but they can't decrypt it unless they are the recipient. The server also deletes a transfer only after the real recipient has decrypted it, so someone else downloading it doesn't remove it.

## Dependencies

| Library | Purpose | Version |
|---|---|---|
| Qt 6 | GUI (client only) | 6.2+ |
| liboqs | ML-KEM-768, ML-DSA-65 (client only) | 0.10+ |
| OpenSSL | AES-GCM, HKDF, SHA-256, RNG | 1.1.1+ (3.x recommended) |
| CMake | Build system | 3.16+ |
| C++17 compiler | GCC 9+, Clang 10+, MSVC 2019+ | |

## Build

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install cmake build-essential qt6-base-dev libssl-dev

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc) && sudo make install && sudo ldconfig
```

### Fedora

```bash
sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl-devel
# then build liboqs as above
```

### macOS

```bash
brew install cmake qt openssl
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOPENSSL_ROOT_DIR=$(brew --prefix openssl) ..
make -j$(sysctl -n hw.ncpu) && sudo make install
```

### Compile

```bash
git clone https://github.com/sova-nova/pq-file-transfer.git
cd pq-file-transfer && mkdir build && cd build
cmake ..            # macOS: cmake -DCMAKE_PREFIX_PATH=$(brew --prefix qt) ..
cmake --build . -j
```

To build only the relay server, for example on a headless machine without Qt or liboqs, use `cmake -DPQ_BUILD_CLIENT=OFF ..`.

### Windows

1. Install Visual Studio 2022 (with the "Desktop development with C++" workload), CMake, Git, Qt 6 for MSVC 2022 64-bit, and [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) (Win64 v3.x, full installer).
2. Build liboqs from the "x64 Native Tools Command Prompt for VS 2022":
   ```cmd
   git clone https://github.com/open-quantum-safe/liboqs.git
   cd liboqs && mkdir build && cd build
   cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_INSTALL_PREFIX=C:\liboqs ..
   cmake --build . --config Release
   cmake --install . --config Release
   ```
3. Configure and build (adjust paths):
   ```cmd
   cmake -G "Visual Studio 17 2022" -A x64 ^
     -DCMAKE_PREFIX_PATH="C:/Qt/6.7.0/msvc2022_64;C:/liboqs" ^
     -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" ..
   cmake --build . --config Release
   C:\Qt\6.7.0\msvc2022_64\bin\windeployqt.exe Release\pq-client.exe
   ```

The Windows build has not been tested yet.

## Usage

### 1. Run the relay server

```bash
./pq-server [--port 9000] [--storage DIR] [--quota-gb 50]
```

The server listens on TCP port 9000. Transfers are kept in a per-user temporary directory, which you can override with `--storage` or `PQ_STORAGE_DIR`. Each transfer is deleted once its recipient confirms it, or after 24 hours. Complete transfers survive a server restart.

To reach the server over the internet, forward its port, or run it on a small VPS. Traffic to the server is not TLS-encrypted, but everything sensitive is already end-to-end encrypted. An observer can see sizes, timing and transfer IDs.

### 2. Start the client and set the server

Run `./pq-client`. On first run it generates your keypairs in `~/.pq-file-transfer/keys/` (`%USERPROFILE%\pq-file-transfer\keys\` on Windows). Enter the relay server as `host:port` in the **Relay server** field; it's remembered between sessions.

**Back up your `keys` folder.** If you lose it, you can't receive anything sent to your old keys, and every contact has to re-add you.

### 3. Exchange keys with a contact

- Click **Export My Public Keys…** and send the two `.key` files to your contact. They are public, so any channel is fine.
- Click **+**, enter a name, and select their two key files.
- **Compare the fingerprint shown with your contact over a call or in person** before confirming.

### 4. Send a file

Choose the contact under **Send to**, click **Send File**, and pick a file. Then click **Copy Transfer ID** and send the ID to the recipient.

### 5. Receive a file

Click **Receive File** and paste the transfer ID. The file is verified, decrypted, and saved to the `downloads` folder (click **Open Downloads** to view it). Existing files are never overwritten. A new copy is saved as `name (1).ext`.

## Protocol version

This is protocol version 2. It is not compatible with v1: the sender and recipient clients and the server all need to be updated together.
