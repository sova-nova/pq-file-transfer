# Handoff: PQ File Transfer → PQ Suite v3

For starting a fresh conversation (with Claude or anyone else) without losing the thread. Read this first, then the design document.

- **Design document:** https://claude.ai/code/artifact/9bfa4d70-d640-4282-a63d-a10e3ac96310
  Protocol design, all decisions, the milestone roadmap. Its **Build log** section at the end records where the code differs from the design. Where they disagree, the build log wins.
- **Code:** this repository. `README.md` documents building, running and using it.

## What exists (version 0.7.0)

A C++17 / Qt 6 application with post-quantum cryptography (ML-KEM-768, ML-DSA-65 via liboqs; AES-256-GCM, HKDF, scrypt via OpenSSL).

| Milestone | State |
|---|---|
| Earlier work | File transfer through a relay (protocol v2), passphrase-protected keys, OS keychain, contact cards, CI releases for Linux and Windows. Done and released. |
| **M0** | Signed identity bundles (card v2). Done and released. |
| **M1** | Mailbox relay: SQLite store, invites, relay signing key pinned by clients, per-contact send tokens, challenge sign-in, expiry. Done and released. |
| **M2** | One-to-one Saved chats: signed records, sealed envelopes, encrypted local history, receipts, message requests, per-contact cards, token revocation, Chats tab. **Built and tested; not yet confirmed on a real Qt build or two real machines.** |
| **M3** | Groups. **In progress.** Decisions settled (below). Steps 2 and 3 of 8 are done: the local history database is at schema version 2 (groups, members, per-member delivery, automatic upgrade from version 1), and the wire formats exist (record version 2 with the `seen` list, the group creation record, envelope inner version 2 with `introduced` bundles). Nothing else of M3 exists yet, and no group can be created from the app. |
| M4 to M8 | Relay archive and restore, attachments in chats, prekeys / forward secrecy, Private chats with timers, hardening. See the design document. |

## Layout

```
protocol/  platform.h (sockets, wait_readable, connect error text), messages.h, protocol.{h,cpp} (framing, helpers),
           relay_protocol.{h,cpp} (v3 payloads and signing inputs), sqlite_helpers.h, scope_exit.h
server/    main.cpp (v2 file transfer + dispatch), relay_store.{h,cpp} (SQLite), relay_service.{h,cpp} (identity, sessions, limits)
client/    crypto_engine, key_store, identity_bundle, sharing (cards, share links, relay invites), transfer_engine (v2),
           relay_client, message_record, envelope, history_store, messaging_engine,
           chat_widget (Chats tab), main_window, key_dialogs, keychain, main
tools/     relay_check.cpp  (pq-relay-check)
tests/     test_sharing, test_keys, test_contacts, test_chat_formats, test_history, test_relay_protocol,
           test_relay_store, test_e2e, test_relay, test_chat
```

## How it fits together

- **One server, two protocols.** `pq-server` decides by a connection's first message: `RELAY_HELLO` means v3 (mailboxes), anything else is v2 file transfer. State for v3 lives in `<storage>/v3` (database and the relay's signing key).
- **Relay trust.** Clients pin the relay ID (SHA-256 of its public key) from the invite; the relay proves it every connection by signing the client's nonce.
- **Mailboxes.** Created with a single-use invite (made on the relay with `--create-invite`). The mailbox has its own random ID and its own ML-DSA key, separate from the identity key. Senders deposit with a send token; the owner signs in and collects.
- **Messages.** A signed record (sender, conversation, recipients hash, time, `own_prev`, `seen`) is sealed in an envelope encrypted to the recipient's long-term ML-KEM key, padded to 4/16/64 KiB. The relay sees only mailbox ID, token hash and the sealed bytes.
- **Local secrets.** History and the mailbox access key are protected by keys derived from the identity's private KEM key (`KeyStore::derive_local_key`), so there is no separate secret file and a passphrase change doesn't affect them.
- **Threading.** `MessagingEngine::pump()` is called from ONE worker thread; every other method is safe from the UI thread. `ChatWidget` owns both, and `MainWindow` deletes it before the key store (the worker uses the keys).

## How verification works (important)

The assistant's sandbox has **no Qt, no CMake, no real liboqs and no SQLite header**. So:

- Code is compiled with `-Wall -Wextra -Wpedantic -Werror` against a fake liboqs and a small SQLite header shim, and the full suites run against those.
- The Qt code (`chat_widget`, `main_window`) is only type-checked against a hand-written stub of the Qt classes. That catches typos and API mismatches in our own code, not Qt misuse.
- **The first CI run is the real test** for the GUI, CMake, Windows and the real liboqs. If it fails, paste the compiler error.
- Test totals at last run: **854 checks, 0 failed** (sharing 117, keys 69, contacts 53, chat_formats 134, history 117, relay_protocol 61, relay_store 60, e2e 48, relay 77, chat 88, relay_setup 30). Linux and macOS only for the process-spawning ones. `ctest --test-dir build --output-on-failure`.

## Operational facts and gotchas

- **Relay and clients must be updated together** when the v3 wire format changes (it did in M2: envelopes now carry a token hash). The relay database migrates itself from schema 1 to 2; back up `<storage>/v3` before upgrading.
- **Back up `<storage>/v3`** on the relay. Losing `relay_private.key` makes every client report "relay changed".
- **An invite does nothing if the relay isn't running.** (A real mix-up that happened; the error message now says so.)
- **Run `--create-invite` as the same user the service runs as.** Otherwise `<storage>/v3` ends up owned by the wrong user and the service can't open it. (The program now detects this at startup and explains how to fix it.)
- **Always use one absolute `--storage` for the server and for `--create-invite`.** A second folder means a second relay identity, and the client reports "relay's identity does not match the one you pinned" (a real mix-up that happened). `--create-invite` now refuses when the storage has no identity (override: `--allow-new-identity`), prints `Relay state:` with the folder it used, and the server warns when it falls back to the temporary default.
- **`--bind` must include an address the client can reach.** A relay bound to the WireGuard address refuses LAN connections.
- **Revoking a card is not enough** to cut someone off: a first message carries a token grant that replaces the card's token on the receiver's side. Use **Revoke access** (`revoke_tokens_for`).
- **All clients must be updated together (new wire formats).** Messages are now written as record version 2 inside envelope inner version 2. A client from before this change can't read them: it drops them silently, and the relay deletes them once the old client acknowledges. New clients still read everything the old ones wrote. The relay itself is unaffected (it never parses records), but update every client before relying on messages between them.
- **`history.db` is upgraded automatically** from schema version 1 to 2 the first time the new app opens it. Before rewriting anything it copies the old file to `history.db.before-v2` next to it (kept, never overwritten). A history made by a *newer* app is refused with an explanation rather than opened. Once the upgrade has been confirmed good, the `.before-v2` copy can be deleted.
- **Clients keep history only on the device** until M4. Back up `~/.pq-file-transfer/` including `history.db`.
- The deployment is a Proxmox VM running the relay with WireGuard. The relay is currently reached at `10.0.0.248:9000` on the LAN; the WireGuard clients use the `10.8.0.x` range. Check the real service unit name and `--bind` before assuming anything.

## Open items

- Confirm M2 on real hardware: set up two clients against the relay, exchange cards, send, check message requests, receipts, revoking, and relay restart.
- Fix any GUI compile errors from the first CI run.
- An in-app way to create invites (today only the operator can, from the command line).
- Storage layout for file transfers: one file per transfer vs per 64 KB chunk (noted earlier).
- macOS build in CI; Windows code signing (SmartScreen warning).
- **M3 groups**, in progress; see "M3: decisions and build order" below. **M4 archive and restore** (removes the "history only on this device" limit) comes after.

## M3: decisions and build order

Settled with the maintainer; they are also in the design document's build log, which wins on any disagreement. A group is at most 16 people including you; membership is fixed at creation.

| # | Decision |
|---|---|
| 1 | The creation record holds the conversation ID, creator, member **fingerprints only**, mode, timer, an optional group title and an optional link to a previous conversation. No bundles (a real bundle is 6,597 bytes, so 16 would be about 105 KB). |
| 2 | The creator sends the other members' self-signed bundles in a new `introduced` list inside the envelope (envelope inner version 2; about 8 bundles fit in one 64 KiB envelope, so two envelopes for 15 others). The creator's signed record names which fingerprints are allowed. |
| 3 | Each member makes a token for each other member, and the grant is forwarded **through the creator**, sealed so the creator can't read it. No grant is needed where two members already hold working tokens as contacts. A new group shows "setting up" until the grants arrive. |
| 4 | `seen` in a record becomes a **list** of the latest hash received from each other member (at most 15), record version 2; version 1 records still parse. |
| 5 | Trust labels: a new `verified` flag (the user compared fingerprints), introduced members kept apart from contacts with who introduced them. Labels: Verified by you / Contact / Introduced by X. ("Key changed" from the first design doesn't apply: identity is the signing-key fingerprint, so a different signing key is a different person; encryption-key changes already produce a notice.) |
| 6 | Receipts go only to the message's author; the sender sees per-member status. |
| 7 | Relay default `max_tokens_per_mailbox` goes from 256 to 1024 (the only relay-side change). |
| 8 | Local database schema 1 to 2 (done): conversations gain kind, state, title, creator, mode, timer and previous-conversation link; members and per-member delivery get their own tables. |

Build order, with what is done:

1. Settle decisions and record them. **Done.**
2. Database migration and per-member delivery, one-to-one behaviour unchanged. **Done** (`HistoryStore`: `create_group`, `conversation`, `set_conversation_state`, `raise_delivery`, `deliveries`; the engine's one-to-one path now uses `raise_delivery`).
3. Creation record, record version 2 and envelope version 2, each with tamper tests on every field. **Done.** `message_record.h`: `RecordType::Conversation` (4), `ConversationInfo` with `conversation_payload`, `parse_conversation_payload` and `conversation_from_record` (checks the creator is a member and the recipients hash matches the list); `Record::seen` is now a list (at most 15, distinct), version 1 records are still read; titles must be strict UTF-8 without control or direction-override characters. `envelope.h`: `Inner::introduced` (declared last, with an initializer, so `{bundle, records}` built positionally keeps its meaning), `encode_inner` and `decode_inner` exposed for tests; inner version 1 is still read. A real bundle is 6,597 bytes: at least 8 fit in one envelope beside a creation record (measured), 15 do not.
4. Engine: create, fan-out, group invite as a request, accept and decline, membership checks, group receipts.
5. Token grants and forwarding through the creator; raise the relay token cap.
6. Trust labels.
7. GUI (last; it can't be built in the assistant's sandbox).
8. Three-user end-to-end tests: an offline member, and hostile cases (a non-member sender, a wrong recipients hash, a replayed creation record, a creator who lies about the members).

Notes for whoever continues: `HistoryStore::raise_delivery` computes a message's overall status as the **lowest** across the conversation's members, so a message never shows as sent or delivered until everyone has it; a receipt from a non-member is ignored. `create_group` on an existing ID returns the existing group unchanged, so a replayed creation record can't alter a group.

## Working agreements

- Explain decisions and tradeoffs in plain language; say plainly what was and wasn't verified.
- Tests come with every change, run with warnings as errors; a failing test is investigated rather than loosened, and test expectations that were wrong are fixed openly.
- Keep the design document's build log current when the code departs from the design.

## Suggested first message in the new conversation

> Continuing a project: post-quantum secure messaging and file transfer (C++/Qt). I'm attaching the repository zip. Read `HANDOFF.md` first, then the design document at the link inside it. M0 to M2 are built. [State what happened since, e.g. whether CI passed and how the two-machine test went.] Next I want to work on: [M3 / M4 / fixes].
