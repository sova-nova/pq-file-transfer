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
| **M3** | Groups. **In progress.** Decisions settled (below). Steps 2 to 7 of 8 are done: the local history database is at schema version 5 (groups, members, per-member delivery, pending invitations, introduced members, member tokens, verified people; automatic upgrade), the wire formats exist (record version 2 with the creation and Forward records, envelope inner version 2), and the engine can create groups, invite, accept and decline, fan out, track delivery per member, send receipts, give members who never met a way to write to each other, and label every member's trust (Verified by you / Contact / Introduced by X); the Chats tab has the matching GUI (groups list, create, invitations, sending, per-member delivery, trust labels and fingerprint verification). What remains of M3 is step 8, the final end-to-end checks, and whatever the maintainer finds when testing the GUI on real Qt (the GUI is only type-checked against a stub here). No group can be created from the app yet; the engine API is tested end to end. |
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
- Test totals at last run: **1,027 checks, 0 failed** (sharing 117, keys 69, contacts 58, chat_formats 141, history 156, relay_protocol 61, relay_store 60, e2e 48, relay 77, chat 88, relay_setup 30, group 122). The group suite runs up to 18 real engines and takes a few minutes. The relay limits mailbox registrations to 10 per minute per address (hard-coded, separate from `--rate-limit`), so tests with many people wait out that window. Linux and macOS only for the process-spawning ones. `ctest --test-dir build --output-on-failure`.

## Operational facts and gotchas

- **Relay and clients must be updated together** when the v3 wire format changes (it did in M2: envelopes now carry a token hash). The relay database migrates itself from schema 1 to 2; back up `<storage>/v3` before upgrading.
- **Back up `<storage>/v3`** on the relay. Losing `relay_private.key` makes every client report "relay changed".
- **An invite does nothing if the relay isn't running.** (A real mix-up that happened; the error message now says so.)
- **Run `--create-invite` as the same user the service runs as.** Otherwise `<storage>/v3` ends up owned by the wrong user and the service can't open it. (The program now detects this at startup and explains how to fix it.)
- **Always use one absolute `--storage` for the server and for `--create-invite`.** A second folder means a second relay identity, and the client reports "relay's identity does not match the one you pinned" (a real mix-up that happened). `--create-invite` now refuses when the storage has no identity (override: `--allow-new-identity`), prints `Relay state:` with the folder it used, and the server warns when it falls back to the temporary default.
- **`--bind` must include an address the client can reach.** A relay bound to the WireGuard address refuses LAN connections.
- **Revoking a card is not enough** to cut someone off: a first message carries a token grant that replaces the card's token on the receiver's side. Use **Revoke access** (`revoke_tokens_for`).
- **All clients must be updated together (new wire formats).** Messages are now written as record version 2 inside envelope inner version 2. A client from before this change can't read them: it drops them silently, and the relay deletes them once the old client acknowledges. New clients still read everything the old ones wrote. The relay itself is unaffected (it never parses records), but update every client before relying on messages between them.
- **Update every client together again, and the relay if you want the larger token limit.** Group members now exchange send tokens through the creator in a new record type (Forward, type 5). A client from before this change drops it, so groups work between updated clients only. The relay's default per-mailbox token limit went from 256 to 1024 (a 16-person group uses 15 per member); the relay needs rebuilding for that, and clients don't care.
- **`history.db` is upgraded automatically** to schema version 5 the first time the new app opens it. From version 1 it must rewrite a table, so it first copies the old file to `history.db.before-v2` next to it (kept, never overwritten); from version 2, 3 or 4 it only adds tables and needs no copy. A history made by a *newer* app is refused with an explanation rather than opened. Once the upgrade has been confirmed good, the `.before-v2` copy can be deleted.
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
4. Engine: create, fan-out, group invite as a request, accept and decline, membership checks, group receipts. **Done.** Public API in `MessagingEngine`: `create_group`, `groups`, `group_messages`, `group_delivery`, `send_group_text`, `mark_group_read`, `set_group_receipts` / `group_receipts_enabled`, `group_invites`, `accept_group_invite`, `decline_group_invite`. How it works: an invitation from a contact waits in `HistoryStore` group invitations until answered, with messages that arrive meanwhile held with it (at most 200) and replayed on accept. An invitation from a non-contact arrives as a message request first (its records, then the introduced bundles, are stored in the request); accepting that person re-handles it as an invitation from a contact. The creator introduces the other members' bundles in `Inner::introduced`, at most 6 per envelope; longer lists are split across envelopes that each repeat the creation record, and a repeat of the identical record adds its bundles but changes nothing else. `Peer` / `resolve_peer` finds someone to verify or write to: a contact, else an introduced member (verifiable, but with no send token until step 5, so `can_send` is false and a group with such members shows `ready == false`). Group records are accepted only from members and only if their recipients hash matches the member list; a creation record for an existing group changes nothing. A receipt goes only to the message's author. The outbox holds one item per recipient; an item's `records` are signed records plus, for invitations, identity bundles to introduce (told apart by whether `parse_record` accepts them).
5. Token grants and forwarding through the creator; raise the relay token cap. **Done.** When a member accepts a group, `queue_group_grants` queues a job (outbox kind 2) for the creator: for each other member except the creator, unless they are a contact who has already used a token of ours. On the relay thread `build_grant_forwards` makes a fresh send token per member (registered with our relay, recorded as issued and bound to that member, so passing it on is reported like a passed-on card), seals a TokenGrant record inside an envelope only that member can open, and wraps it in a signed `Forward` record (type 5) to the creator, four per envelope. The creator (`handle_group_record`) checks the sender and the target are members of a group it created and deposits the sealed envelope unread (outbox kind 3, `OUTBOX_KIND_RELAY`). The member who gets it stores the token for that group and that member only (`HistoryStore::member_token`, encrypted); `resolve_peer(fp, conversation_id)` uses it when there is no other way to write to them, so the group becomes ready. Grants that arrive before the invitation is answered are held with it. A forwarded grant arrives through the creator's token, so it is not counted as use of a card. Someone known only from a group (not a contact) gets no first-message introduction. The relay's default token limit is 1024. If the creator is offline, members who aren't contacts stay "not ready" until it returns (the relay holds the envelopes).
6. Trust labels. **Done.** `HistoryStore` keeps a table of verified people (`set_verified`, `is_verified`): it is about the person, so it holds whether they are a contact or only known from a group, and carries over if one becomes the other. `MessagingEngine::GroupMember` now has `trust` (`Unknown`, `Introduced`, `Contact`, `Verified`), `introduced_by` (a name) and a ready-made `label` ("Verified by you", "Contact", "Introduced by Alice", "Unknown"); `ChatSummary` has `verified`. `set_verified(fp, bool)` works for contacts and introduced members (false for strangers). `accept_request` marks the person verified, because the app has the user check their fingerprint first. A newer bundle from an introduced member with a different encryption key raises the same "is using a new encryption key" notice as for contacts. (The GUI side of this, including marking a contact verified after the add-contact fingerprint dialog, is slice 4 of step 7.)
7. GUI (last; it can't be built in the assistant's sandbox, so GUI changes are only type-checked against a hand-written Qt stub). **In progress, in slices.** Slice 1 done: `ChatWidget` has a "Groups" list under the contacts (hidden until a group exists) showing each group's title, unread count and "(setting up)" while some member can't be written to; the tooltip lists members with their trust labels (escaped, since titles and names come from other people); selecting a group shows its messages read-only (sender names, delivery words), marks them read, and the receipt checkboxes work per group; the header lists members and who we can't write to yet. Selecting a contact and a group is mutually exclusive. Slice 2 done: a "New group…" button (name plus tick-boxes for contacts you can message, up to 15; the engine validates) and a "Group invitations (N)" button that walks through pending invitations (Join, Decline, Decide later) showing the creator, the others with their trust labels and a note about "Introduced" people, and how many messages arrived while waiting; creating or joining selects the group. Plain-text sending to a group works too (queued per member, whether or not everyone is reachable yet), in `send_current`. An invitation from someone who isn't a contact still arrives as a message request first. Slice 3 done: your messages in a group show how far they have got in true terms ("sent to 2 of 3", "sent to everyone, delivered to 1 of 3", "delivered to everyone", "read by everyone"; computed for the newest 50 outgoing messages not yet read by all), and clicking one opens a plain-text dialog with each member's own state and why it may be stuck (can't write to them yet / sent but not confirmed, e.g. receipts off or the relay still holding it). It relies on `QListWidget::itemClicked` firing with the list in NoSelection mode, which is not verified. Slice 4 done: the group header lists members with their trust labels; a header button reads "Members…" for a group (a dialog listing everyone with label, who made the group and who can't be written to yet, with a Fingerprint… button) and "Verify…" for a contact (their fingerprint, with "It matches: mark as verified" or "Remove verified mark"); a contact's header shows "(verified by you)" or "(not verified)"; and `main_window.cpp` `finish_add_contact` calls `ChatWidget::mark_verified(fp)` after the user answers "Yes" to "Does the fingerprint match?". Message-request accept already verifies (engine).
8. Three-user end-to-end tests: an offline member, and hostile cases (a non-member sender, a wrong recipients hash, a replayed creation record, a creator who lies about the members).

Notes for whoever continues: `HistoryStore::raise_delivery` computes a message's overall status as the **lowest** across the conversation's members, so a message never shows as sent or delivered until everyone has it; a receipt from a non-member is ignored. `create_group` on an existing ID returns the existing group unchanged, so a replayed creation record can't alter a group.

## Working agreements

- Explain decisions and tradeoffs in plain language; say plainly what was and wasn't verified.
- Tests come with every change, run with warnings as errors; a failing test is investigated rather than loosened, and test expectations that were wrong are fixed openly.
- Keep the design document's build log current when the code departs from the design.

## Suggested first message in the new conversation

> Continuing a project: post-quantum secure messaging and file transfer (C++/Qt). I'm attaching the repository zip. Read `HANDOFF.md` first, then the design document at the link inside it. M0 to M2 are built. [State what happened since, e.g. whether CI passed and how the two-machine test went.] Next I want to work on: [M3 / M4 / fixes].
