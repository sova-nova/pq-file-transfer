#pragma once

#include <optional>
#include <string>

// Thin wrapper over the operating system's secret store (Windows Credential Manager,
// macOS Keychain, or the Linux Secret Service / KWallet), via QtKeychain. The app uses it
// to remember the key passphrase so the user doesn't have to type it on every start.
//
// When the app is built without QtKeychain, available() is false and every call is a harmless
// no-op, so callers never need to care.
namespace keychain {

// True if this build has keychain support. (The OS may still have no keyring running, in
// which case store() fails and load() finds nothing; callers fall back to asking.)
bool available();

// Returns the saved secret, or std::nullopt if there is none or the keychain can't be reached.
std::optional<std::string> load(const std::string& account);

// Returns false if it could not be saved.
bool store(const std::string& account, const std::string& secret);

// Deleting something that isn't there counts as success.
bool remove(const std::string& account);

}  // namespace keychain
