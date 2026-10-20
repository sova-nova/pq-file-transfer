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
- **No forward secrecy**: transfers are encrypted to the recipient's long-term key. Anyone who later obtains a recipient's `private_kem` file, together with a stored ciphertext, can decrypt it. That is why the private keys can be protected by a passphrase (see below).

### Trust model

Security depends on having your contacts' **real** public keys. Public keys can be exchanged over any channel, such as email or chat. When you add a contact, though, the app shows their fingerprint, and you should confirm it with them over a channel where you know you're talking to them, like in person or on a call. If an attacker swaps the key files in transit and you skip this check, the attacker can read the files you send.

Anyone who has a transfer ID can download the ciphertext, but they can't decrypt it unless they are the recipient. The server also deletes a transfer only after the real recipient has decrypted it, so someone else downloading it doesn't remove it.

## Dependencies

| Library | Purpose | Version |
|---|---|---|
| Qt 6 | GUI (client only) | 6.2+ |
| liboqs | ML-KEM-768, ML-DSA-65 (client, and the relay for signatures) | 0.10+ |
| OpenSSL | AES-GCM, HKDF, scrypt, SHA-256, RNG | 1.1.1+ (3.x recommended) |
| SQLite 3 | The relay's mailbox storage (server and tests) | 3.35+ |
| QtKeychain | Remembering the passphrase in the OS keychain (client only, optional) | 0.14+ built for Qt 6 |
| CMake | Build system | 3.16+ |
| C++17 compiler | GCC 9+, Clang 10+, MSVC 2019+ | |

## Build

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install cmake build-essential qt6-base-dev libssl-dev libsqlite3-dev

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

To build only the relay server and the command-line tools, for example on a headless machine without Qt, use `cmake -DPQ_BUILD_CLIENT=OFF ..`. They still need liboqs and SQLite. You don't have to compile them on the relay machine at all: the release page has a ready-made `pq-server-linux-x86_64` (it needs the system's `libssl3` and `libsqlite3-0`, both present on current Debian and Ubuntu).

**Optional: OS keychain support.** If QtKeychain for Qt 6 is installed, CMake finds it and the client can remember your key passphrase. Without it the client still works and just asks for the passphrase at every start. To build it yourself:

```bash
sudo apt install libsecret-1-dev      # Linux only
git clone https://github.com/frankosterfeld/qtkeychain.git
cmake -S qtkeychain -B qtkeychain/build -DBUILD_WITH_QT6=ON -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build qtkeychain/build -j && sudo cmake --install qtkeychain/build
```

Add `-DPQ_REQUIRE_KEYCHAIN=ON` when configuring the client to make the build fail instead of silently leaving it out. The configure output says `OS keychain support: ON` or `OFF`.

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
./pq-server [--port 9000] [--bind ADDR] [--storage DIR] [--quota-gb 50]
```

One server, one port, two protocols. It tells them apart by a connection's first message, so existing file-transfer clients keep working while the new mailbox features are built.

- **File transfers (protocol v2).** Transfers are kept in a per-user temporary directory, which you can override with `--storage` or `PQ_STORAGE_DIR`. Each transfer is deleted once its recipient confirms it, or 24 hours after it was uploaded. Complete transfers survive a restart, and their 24 hours keep counting while the server is down.
- **Mailboxes (protocol v3).** Sealed envelopes are held until their owner collects them. State lives in `<storage>/v3`, which holds the database and **the relay's signing key**. Back that folder up (see below).

`--bind ADDR` limits the server to one IPv4 address. If you reach it over WireGuard, bind it to the tunnel address (for example `--bind 10.8.0.1`) so that it never listens on your LAN or the internet, even if a firewall rule is wrong. The default, `0.0.0.0`, listens on every interface.

To reach the server over the internet, forward its port, or run it on a small VPS. Traffic to the server is not TLS-encrypted, but everything sensitive is already end-to-end encrypted. An observer can see sizes, timing and transfer IDs.

#### The mailbox relay

**Identity.** On first start the relay generates a signing key and prints its **Relay ID**, the SHA-256 of the public key. Clients pin that ID, and the relay proves it holds the matching key every time a client connects, so a fake relay, a hijacked address or a replayed answer is detected even outside WireGuard. That is why the key matters: if you rebuild the machine without `<storage>/v3/relay_private.key`, every client sees "relay changed" and refuses to talk to the new one. The private key is stored with owner-only permissions and is not passphrase-protected, because the relay has to start unattended.

**Invites.** Nobody can create a mailbox without an invite, so strangers can't fill your disk. Make one on the relay machine. Use **the same `--storage` folder, as the same user,** that the running relay uses: that folder holds the relay's identity, and an invite carries that identity. Always give the server and `--create-invite` the same absolute `--storage` (the default is a temporary folder, which is a poor place for a signing key):

```bash
./pq-server --storage /var/lib/pq-relay --create-invite --public-address 10.8.0.1:9000
```

It prints a one-time code and a ready-to-paste invite string, `pqft-relay://10.8.0.1:9000/<relay id>/<code>`. That single string carries where the relay is, which key to trust, and the code, so the first connection is already verified. An invite works once and expires after 14 days.

It also prints `Relay state:`, the folder it used, and the Relay ID, which must equal the one the running relay printed at startup. If the storage has no relay identity yet, `--create-invite` refuses instead of silently creating a second identity (a different `--storage` is the usual cause; clients would report "does not match the one you pinned"). Add `--allow-new-identity` only for a brand-new relay that has never been started.

**Members vouching for friends.** You don't have to make every invite yourself. Anyone with a mailbox on your relay can press **Relay invites…** in the app to make a one-time invite for a friend. The same dialog shows which of your invites are still unused (and when they expire), when people joined through you, and lets you cancel an unused invite if it went to the wrong place. The relay records who vouched for each person, so there is always someone accountable, and a stranger who merely knows your relay's address can't get an invite. By default one member may have 3 unused invites at once and may invite 10 people in all (`--member-invites` and `--member-invites-total`; `--member-invites 0` turns this off, leaving only your own). An invite is a secret, and like a send token it crosses the network unencrypted between the app and the relay, so keep the relay on a network you trust, such as the WireGuard tunnel.

To see who is on the relay and who vouched for whom, or to undo it:

```bash
./pq-server --storage /var/lib/pq-relay --list-mailboxes
./pq-server --storage /var/lib/pq-relay --remove-mailbox a1b2c3d4e5f6            # just that mailbox
./pq-server --storage /var/lib/pq-relay --remove-mailbox a1b2c3d4e5f6 --with-invitees   # and everyone it invited
```

The first columns of `--list-mailboxes` are the IDs to use (at least 8 characters). Removing a mailbox deletes its queued messages and its owner can no longer sign in. A relay with existing mailboxes upgrades its database automatically the first time the new version starts.

**Checking it from the outside.** `pq-relay-check` confirms a relay is reachable and genuine from wherever you run it, through the tunnel and the firewall:

```bash
pq-relay-check 10.8.0.1:9000                 # reachable? prints the Relay ID to compare
pq-relay-check 10.8.0.1:9000 <relay id>      # ...and checks it matches the one you were given
pq-relay-check 'pqft-relay://...'            # full round trip using one invite (it is used up)
```

**What the relay sees and stores.** Random mailbox IDs, the hash of each send token, and sealed envelopes it cannot read. It never sees names, identity keys, who sent a message, or content. Envelopes are deleted when their owner acknowledges them, or when their lifetime runs out (never more than 30 days).

**Limits and settings.**

| Flag | Default | Meaning |
|---|---|---|
| `--mailbox-quota-kib N` | 65536 | Queued bytes allowed per mailbox |
| `--rate-limit N` | 120 | Deposits per minute, per send token and per client address |
| `--sweep-seconds N` | 60 | How often expired envelopes are removed |
| `--allow-new-identity` | off | With `--create-invite`: create the relay's identity if the storage has none |
| `--max-archives N` | 1000 | Chat archives the relay will hold |
| `--archive-quota-mib N` | 512 | Encrypted bytes allowed per chat archive |
| `--member-invites N` | 3 | Unused invites one member may have at once; 0 turns member invites off |
| `--member-invites-total N` | 10 | Most people one member may ever invite |
| `--list-mailboxes` | | Show every mailbox, who vouched for it and what is queued, then exit |
| `--remove-mailbox ID` | | Remove a mailbox (ID prefix of 8+ characters), then exit |
| `--with-invitees` | | With `--remove-mailbox`: also everyone it invited, and theirs |

A systemd unit for the relay (the `ExecStart` line is the important part):

```ini
[Service]
User=pqrelay
StateDirectory=pq-relay
ExecStart=/usr/local/bin/pq-server --port 9000 --bind 10.8.0.1 --storage /var/lib/pq-relay --quota-gb 20
Restart=on-failure
```

**Status.** The relay core is finished and tested, but the app can't send messages through it yet. Chats arrive in the next milestones.

### 2. Start the client and set the server

Run `./pq-client`. On first run it generates your keypairs in `~/.pq-file-transfer/keys/` (`%USERPROFILE%\pq-file-transfer\keys\` on Windows), after asking whether to protect them with a passphrase (see below). Enter the relay server as `host:port` in the **Relay server** field; it's remembered between sessions.

**Back up your `keys` folder, and your passphrase if you set one.** If you lose either, you can't receive anything sent to your old keys, and every contact has to re-add you.

### Protecting your keys with a passphrase

Your private keys let you read files sent to you. If someone copies them, from a stolen laptop or an unprotected backup, they can read everything ever sent to you. A passphrase encrypts the key files on disk, so a copied file is useless without it.

- **First run:** the app explains this and asks you to choose a passphrase (at least 8 characters; a few random words work well).
- **Upgrading from an earlier version:** the app offers to protect your existing keys. Your fingerprint doesn't change, so contacts don't need to do anything.
- **Skipping is allowed.** It's your computer and your choice. **Skip (not recommended)** leaves the keys unprotected, and the app won't keep asking. You can protect them later from **Key Protection…**.
- **Key Protection…** lets you set, change or remove the passphrase at any time. The status line above it shows whether your keys are currently protected.
- **A forgotten passphrase cannot be recovered.** There is no reset: the keys are encrypted with it.

The passphrase is turned into an encryption key with scrypt (128 MiB of memory, so guessing is slow and expensive even for an attacker with a lot of hardware), and the keys are encrypted with AES-256-GCM. Each protected file also authenticates which key it holds, so the two files can't be swapped. While the app is open, the decrypted keys are held in memory, and they are wiped when you close it.

### Remembering the passphrase (OS keychain)

If the app was built with keychain support, the passphrase prompt has a **Remember on this computer** checkbox (ticked by default). The passphrase is then kept in your operating system's own secret store, so the app unlocks your keys without asking. In normal use you only type the passphrase again after reinstalling, or on a new computer.

| System | Where it is kept |
|---|---|
| Windows | Credential Manager |
| macOS | Keychain (you may see a one-time "allow access" prompt) |
| Linux | Secret Service: GNOME Keyring, KWallet, or any compatible keyring |

Nothing needs configuring. The one catch is Linux: a keyring service must be running. That is normal on Ubuntu, Fedora and KDE desktops but not on minimal window managers or over SSH. If there isn't one, the app tells you the passphrase couldn't be saved and simply asks for it at each start.

**What this does and doesn't protect against.** The keychain is unlocked by your operating-system login. A copied key file, a stolen disk or an unencrypted backup stays useless, because the passphrase isn't in the file. It does *not* protect against malware running as you, or someone using your logged-in session, which holds for any desktop app. You can remove the saved passphrase at any time from **Key Protection… → Forget saved passphrase**.

**Limits.** The passphrase and unlocked keys sit in ordinary process memory while the app runs, so this doesn't defend against someone who can read that memory, or against a swap file or hibernation image on an unencrypted disk. Full-disk encryption covers that.

### 3. Add a contact

The easiest way is a **contact card**: one line of text that holds a name, your public keys and your relay server, signed with your identity key.

1. **Copy My Contact Card**, then paste it into a message to your contact.
2. They click **+** and choose **Paste contact card…**. (If a card is already on their clipboard it is filled in for them.)
3. **Compare the fingerprint shown with your contact over a call or in person** before confirming. A signature proves a card wasn't altered on the way, but not who made it, so this check is what makes it trustworthy.
4. If the card names a relay server different from theirs, the app asks before switching. It never switches silently.

Do this in both directions: each of you needs the other as a contact, so that you can send to them and recognise files from them.

**Why cards are signed.** Your fingerprint is a hash of your signing key. Before version 0.5, a card carried the encryption key unsigned, so someone who altered a card in transit could keep your signing key (the fingerprint still matched) and substitute their own encryption key, and then read files sent to you. Now the card is a signed *identity bundle* that binds the two keys together, and any change to the encryption key breaks the signature. Fingerprints did not change, so contacts you already verified stay verified.

**Older contacts.** Contacts added from a version 1 card or from key files show **(key not verified)** in the list, and the app asks you to confirm before sending to them. Ask them to update and send a new card. Importing it repairs the contact in place, with no new fingerprint check needed (the signing key is the same), and replaces the saved encryption key if it was different. Newer cards from people you already have are applied the same way, which also covers someone rotating their encryption key. A card with a different signing key is a key change, and the app asks you to verify the new fingerprint again.

The older method still works: **Export Key Files…** saves two `.key` files, and **+** → **Choose key files…** adds them. Contacts added that way are marked as not verified.

### 4. Send a file

Choose the contact under **Send to**, click **Send File**, and pick a file. Then click **Copy Share Link** and send the link to the recipient. It looks like `pqft://10.8.0.1/0123abcd…` and includes the relay server. **Copy Transfer ID** gives just the 32-character ID if you prefer.

The link or ID lets anyone download the encrypted file, but only the recipient can decrypt it. Send it over any channel.

### 5. Receive a file

Click **Receive File** and paste the share link (or the bare transfer ID). If the link names a different relay server than yours, the app asks which one to use. The file is verified, decrypted, and saved to the `downloads` folder (click **Open Downloads** to view it). Existing files are never overwritten. A new copy is saved as `name (1).ext`.

### Messaging: one-to-one Saved chats

The **Chats** tab sends messages through a mailbox relay. Messages are end-to-end encrypted and signed, work when the other person is offline (the relay holds them until they connect), and are kept in an encrypted history on your computer.

**1. Set up messaging (once).** Click **Set up messaging…** and paste the invite string the relay's operator gave you (see [the mailbox relay](#the-mailbox-relay)). The app shows the relay's identity, pins it, and creates your mailbox. Nothing the relay learns can be tied to your name or your identity keys: your mailbox has its own random ID and its own key.

**2. Give each person their own card.** Use **Copy My Contact Card** on the Files tab. With messaging set up it asks who the card is for, then makes a card that carries a permission to message you that exists only for that card. Revoke one card and only that card stops working. Under **Cards issued…** you can see every card, whether it has been used, and by whom. If a card is first used by one person and later by another, you are warned that it was probably passed on.

**3. Add each other.** Add the card you were given with **+** as before, including the fingerprint check. Cards from before version 0.7 don't carry a messaging address: ask for a new one. Importing it updates the contact in place.

**4. Chat.** Pick a contact and write. Each message shows its state: waiting to send, sent (the relay has it), delivered (their app stored it), read. Both kinds of receipt can be turned off per chat, and each person controls the receipts they send. A message you write while the relay or the other person is unreachable waits in a queue and goes out by itself.

**Message requests.** If someone writes to you who isn't a contact (they had a card of yours), it arrives as a **message request**: you see their fingerprint, the name they gave themselves and what they wrote, and nothing else happens until you decide. **Accept** asks you to verify their fingerprint first, then adds them and delivers what they sent. **Decline** deletes it.

**Revoking.** On a chat, **Revoke access…** removes every card and permission that person has been given. They can no longer send you anything until you give them a new card. Their earlier messages stay in your history.

**What protects your messages.**

- Each message is a record signed with the sender's identity key: who sent it, to whom, in which conversation, when, and what they had already sent and received. The recipient checks the signature against the sender's key, and checks the record is for exactly these two people, so a message can't be forged, edited or redirected to someone else.
- Each envelope is encrypted to the recipient alone with a fresh key. The sender's identity is inside it, so the relay can't see who is writing to whom, and sizes are padded to 4, 16 or 64 KiB.
- Your history is encrypted on disk, row by row, with a key derived from your identity's private key. It is locked by the same passphrase as your keys and stays readable when you change that passphrase. A copy of `history.db` is useless without your keys.
- A message whose sender's earlier message never arrived is shown, flagged as following a gap.

**What it doesn't do yet.**

- **No forward secrecy.** Envelopes are encrypted to your long-term key, so anyone who later gets your private key and a recorded envelope can read it. One-time prekeys and an X25519 hybrid are a later milestone.
- **History lives only on your computer.** Back up your keys folder *and* `history.db` (both in `~/.pq-file-transfer/`; the file is useless without the keys). Restoring history on a new device, a relay-held archive, and deleting chats by mutual agreement come in a later milestone.
- **One device per identity, one relay, no groups, no files in chats yet.**

## Tests

The tests need liboqs but not Qt:

```bash
cmake -S . -B build -DPQ_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

- `sharing` checks server addresses, contact cards (both versions) and share links, and signed identity bundles, including damaged and hostile input and the key-swap attack above.
- `contacts` checks verified and unverified contacts and the rules for importing newer, older and rotated bundles (Linux and macOS only).
- `keys` checks the passphrase protection: the encrypted file format (including tampering, swapped files and hostile settings) and locking, unlocking, changing and removing the passphrase, including a crash in the middle of protecting (Linux and macOS only).
- `chat_formats` checks the signed message records (every bit of the signed body, forgery, redirection, receipts) and the sealed envelope (tampering with every byte, the wrong recipient, size padding).
- `history` checks the encrypted history store: nothing readable on disk, a wrong key reads nothing, rows copied into other rows or conversations are rejected, statuses only move forward, and the outgoing queue, requests and issued tokens (Linux and macOS only).
- `chat` starts a real relay and several simulated users and checks the whole flow: setup, cards and per-contact tokens, messages both ways with receipts, offline delivery, restarts, hostile envelopes (garbage, forged senders, strangers, replays, redirected and gapped records), message requests, a passed-on card, revoking and recovering, receipt settings, the relay going away and coming back, and locked keys (Linux and macOS only).
- `relay_protocol` checks the v3 message encodings, every truncation and 3000 random corruptions of each, and the signing inputs.
- `relay_store` checks the relay's database with a controlled clock: invites, mailbox limits, send tokens, ordering, expiry, quotas, acknowledgement scoping and persistence (Linux and macOS only).
- `relay` starts a real relay and checks registration and invites, sign-in (including replayed and mis-bound signatures), deposits, offline delivery, push, restarts, expiry, rate limits and hijack attempts, then runs a scripted hostile relay against the client: wrong key, replayed answers, silence, duplicated and malformed envelopes, and a frame declaring 4 GiB (Linux and macOS only).
- `e2e` starts a real `pq-server` and runs transfers between three simulated users, two of whom use passphrase-protected keys (Linux and macOS only). It covers wrong recipients, locked keys, unknown senders, tampering, truncation, hostile file names, and server restarts and expiry.

The release workflow runs the same tests against the real liboqs before it publishes anything.

## Protocol version

This is protocol version 2. It is not compatible with v1: the sender and recipient clients and the server all need to be updated together.
