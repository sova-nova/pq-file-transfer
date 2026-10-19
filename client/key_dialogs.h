#pragma once

#include <QString>

#include <string>

class QWidget;

enum class DialogOutcome { Cancelled, Accepted, Skipped };

struct PassphraseChoice {
    DialogOutcome outcome = DialogOutcome::Cancelled;
    std::string passphrase;  // UTF-8, Unicode-normalised (NFC) so it types the same on every OS
    bool remember = false;   // "Remember on this computer" was ticked (only if the keychain is available)
};

// Asks for a new passphrase twice. `explanation` is shown above the fields. With `allow_skip`
// there is a "Skip (not recommended)" button (outcome Skipped); without it, a Cancel button.
// Closing the window is always Cancelled.
PassphraseChoice ask_new_passphrase(QWidget* parent, const QString& title, const QString& explanation,
                                    bool allow_skip);

// Asks for the existing passphrase. `offer_remember` adds the keychain checkbox (if available).
PassphraseChoice ask_existing_passphrase(QWidget* parent, const QString& title, const QString& message,
                                         bool offer_remember, const QString& action_text = "Unlock");
