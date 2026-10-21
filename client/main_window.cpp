#include "main_window.h"
#include "crypto_engine.h"
#include "chat_widget.h"
#include "key_dialogs.h"
#include "keychain.h"

#include <QAction>
#include <QClipboard>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QProgressBar>
#include <QTabWidget>
#include <QPushButton>
#include <QSettings>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <filesystem>
#include <optional>

namespace {

const char* const SERVER_SETTING = "server";
const char* const DEFAULT_SERVER = "127.0.0.1:9000";

QString qstr(const std::string& s) { return QString::fromStdString(s); }

QString formatted_fingerprint(const std::string& fp) {
    return qstr(CryptoEngine::format_fingerprint(fp));
}

std::vector<uint8_t> read_small_file(const QString& path, qint64 max_size) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() <= 0 || f.size() > max_size) return {};
    QByteArray data = f.readAll();
    return std::vector<uint8_t>(data.begin(), data.end());
}

// The server field as a parsed address, if it holds a valid one.
std::optional<ServerAddress> configured_server(const QLineEdit* edit) {
    return parse_server_address(edit->text().toStdString());
}

QString default_display_name() {
    QString name = qEnvironmentVariable("USER");
    if (name.isEmpty()) name = qEnvironmentVariable("USERNAME");
    return name;
}

const char* const KEY_PROTECTION_DECIDED = "key_protection_decided";

// Explains key protection, and what the keychain does for convenience, before asking.
QString protection_explanation(const QString& heading) {
    QString text = heading +
        "\n\nYour private keys let you read files that are sent to you and prove that files from you "
        "are really yours. If someone copies them, for example from a stolen laptop or an unprotected "
        "backup, they can read everything sent to you. A passphrase locks them.\n\n";
    if (keychain::available()) {
        text += "With \"Remember on this computer\" ticked, the passphrase is kept in your system's "
                "keychain (Windows Credential Manager, macOS Keychain or the Linux keyring). You will "
                "rarely have to type it again, typically only after reinstalling or on a new computer.\n\n";
    } else {
        text += "You will be asked for the passphrase each time you start the app.\n\n";
    }
    text += "A forgotten passphrase cannot be recovered. Use at least 8 characters; a few random words work well.";
    return text;
}

QLabel* plain_label(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);  // never interpret server/sender text as HTML
    label->setWordWrap(true);
    return label;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("PQ File Transfer");
    setMinimumSize(480, 560);

    // Two tabs: the existing file transfer, and chats. Everything below up to the Chats tab is the
    // Files page, built into `layout`.
    auto* tabs = new QTabWidget(this);
    setCentralWidget(tabs);
    auto* files_page = new QWidget(tabs);
    auto* layout = new QVBoxLayout(files_page);
    tabs->addTab(files_page, "Files");

    auto* title = new QLabel("PQ File Transfer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size: 18px; font-weight: bold;");
    layout->addWidget(title);

    status_label_ = plain_label("Status: Ready", this);

    std::string key_problem;
    try {
        keystore_ = std::make_unique<KeyStore>();
        if (!setup_keys(key_problem)) {
            keystore_.reset();
            layout->addWidget(status_label_);
            layout->addStretch();
            show_error(key_problem);
            return;
        }
    } catch (const std::exception& e) {
        keystore_.reset();
        layout->addWidget(status_label_);
        layout->addStretch();
        show_error(std::string("Key setup failed: ") + e.what());
        return;
    }
    engine_.set_keystore(keystore_.get());  // transfers use the unlocked keys held by the app

    // --- Identity ---
    auto* fingerprint_hint = plain_label("Your fingerprint. Contacts should check it with you before trusting your keys:", this);
    fingerprint_hint->setAlignment(Qt::AlignCenter);  // centered like the fingerprint beneath it
    layout->addWidget(fingerprint_hint);
    fingerprint_label_ = plain_label(formatted_fingerprint(keystore_->own_fingerprint()), this);
    fingerprint_label_->setAlignment(Qt::AlignCenter);
    fingerprint_label_->setStyleSheet("font-family: monospace;");
    fingerprint_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(fingerprint_label_);

    auto* identity_layout = new QHBoxLayout();
    copy_card_button_ = new QPushButton("Copy My Contact Card", this);
    copy_card_button_->setToolTip("One line of text to send to a contact so they can add you");
    export_keys_button_ = new QPushButton("Export Key Files…", this);
    identity_layout->addWidget(copy_card_button_);
    identity_layout->addWidget(export_keys_button_);
    layout->addLayout(identity_layout);

    key_status_label_ = plain_label("", this);
    layout->addWidget(key_status_label_);
    key_protection_button_ = new QPushButton("Key Protection…", this);
    auto* key_menu = new QMenu(key_protection_button_);
    QAction* set_action = key_menu->addAction("Set a passphrase…");
    QAction* change_action = key_menu->addAction("Change passphrase…");
    QAction* remove_action = key_menu->addAction("Remove passphrase (less secure)…");
    key_menu->addSeparator();
    QAction* forget_action = key_menu->addAction("Forget saved passphrase");
    connect(set_action, &QAction::triggered, this, [this] { set_passphrase_action(); });
    connect(change_action, &QAction::triggered, this, [this] { change_passphrase_action(); });
    connect(remove_action, &QAction::triggered, this, [this] { remove_passphrase_action(); });
    connect(forget_action, &QAction::triggered, this, [this] { forget_saved_passphrase(); });
    connect(key_menu, &QMenu::aboutToShow, this, [this, set_action, change_action, remove_action, forget_action] {
        const bool protected_keys = keystore_->private_keys_protected();
        set_action->setEnabled(!protected_keys);
        change_action->setEnabled(protected_keys);
        remove_action->setEnabled(protected_keys);
        forget_action->setEnabled(protected_keys && keychain::available());
    });
    key_protection_button_->setMenu(key_menu);
    layout->addWidget(key_protection_button_);
    update_key_status();
    layout->addSpacing(10);

    // --- Server ---
    auto* server_layout = new QHBoxLayout();
    server_layout->addWidget(new QLabel("Relay server:", this));
    server_edit_ = new QLineEdit(QSettings().value(SERVER_SETTING, DEFAULT_SERVER).toString(), this);
    server_edit_->setPlaceholderText("host:port");
    server_layout->addWidget(server_edit_, 1);
    layout->addLayout(server_layout);

    // --- Recipient ---
    auto* recipient_layout = new QHBoxLayout();
    recipient_layout->addWidget(new QLabel("Send to:", this));
    recipient_combo_ = new QComboBox(this);
    recipient_combo_->setMinimumWidth(150);
    recipient_layout->addWidget(recipient_combo_, 1);
    add_contact_button_ = new QPushButton("+", this);
    add_contact_button_->setToolTip("Add contact");
    add_contact_button_->setMaximumWidth(30);
    remove_contact_button_ = new QPushButton("−", this);
    remove_contact_button_->setToolTip("Remove selected contact");
    remove_contact_button_->setMaximumWidth(30);
    recipient_layout->addWidget(add_contact_button_);
    recipient_layout->addWidget(remove_contact_button_);
    layout->addLayout(recipient_layout);

    // --- Actions ---
    send_button_ = new QPushButton("Send File", this);
    receive_button_ = new QPushButton("Receive File", this);
    cancel_button_ = new QPushButton("Cancel", this);
    send_button_->setMinimumHeight(40);
    receive_button_->setMinimumHeight(40);
    cancel_button_->setEnabled(false);
    layout->addWidget(send_button_);
    layout->addWidget(receive_button_);
    layout->addWidget(cancel_button_);
    layout->addSpacing(10);

    progress_bar_ = new QProgressBar(this);
    progress_bar_->setRange(0, 100);
    progress_bar_->setValue(0);
    layout->addWidget(progress_bar_);

    transfer_id_label_ = plain_label("", this);
    transfer_id_label_->setAlignment(Qt::AlignCenter);
    transfer_id_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(transfer_id_label_);

    auto* util_layout = new QHBoxLayout();
    copy_link_button_ = new QPushButton("Copy Share Link", this);
    copy_link_button_->setEnabled(false);
    copy_id_button_ = new QPushButton("Copy Transfer ID", this);
    copy_id_button_->setEnabled(false);
    util_layout->addWidget(copy_link_button_);
    util_layout->addWidget(copy_id_button_);
    layout->addLayout(util_layout);
    open_downloads_button_ = new QPushButton("Open Downloads", this);
    layout->addWidget(open_downloads_button_);

    layout->addStretch();
    layout->addWidget(status_label_);

    refresh_contacts();

    // Engine callbacks run on the worker thread; marshal them to the UI thread.
    engine_.on_status = [this](const std::string& msg) {
        QMetaObject::invokeMethod(this, [this, msg]() { update_status(msg); });
    };
    engine_.on_progress = [this](double fraction) {
        QMetaObject::invokeMethod(this, [this, fraction]() { update_progress(fraction); });
    };
    engine_.on_error = [this](const std::string& error) {
        QMetaObject::invokeMethod(this, [this, error]() { show_error(error); });
    };
    engine_.on_complete = [this](const std::string& filepath) {
        QMetaObject::invokeMethod(this, [this, filepath]() { show_complete(filepath); });
    };
    engine_.on_transfer_id = [this](const std::string& id) {
        QMetaObject::invokeMethod(this, [this, id]() { show_transfer_id(id); });
    };

    connect(send_button_, &QPushButton::clicked, this, &MainWindow::start_send);
    connect(receive_button_, &QPushButton::clicked, this, &MainWindow::start_receive);
    connect(cancel_button_, &QPushButton::clicked, this, [this] {
        engine_.cancel();
        update_status("Cancelling...");
    });
    connect(add_contact_button_, &QPushButton::clicked, this, &MainWindow::add_contact);
    connect(remove_contact_button_, &QPushButton::clicked, this, &MainWindow::remove_contact);
    connect(copy_card_button_, &QPushButton::clicked, this, &MainWindow::copy_contact_card);
    connect(export_keys_button_, &QPushButton::clicked, this, &MainWindow::export_keys);
    connect(copy_link_button_, &QPushButton::clicked, this, &MainWindow::copy_share_link);
    connect(copy_id_button_, &QPushButton::clicked, this, &MainWindow::copy_transfer_id);
    connect(open_downloads_button_, &QPushButton::clicked, this, &MainWindow::open_downloads);
    connect(server_edit_, &QLineEdit::editingFinished, this, &MainWindow::save_server_setting);

    // The Chats tab owns the messaging engine and its worker thread.
    chat_widget_ = new ChatWidget(*keystore_, keystore_->app_dir() / "history.db", tabs);
    const int chats_tab = tabs->addTab(chat_widget_, "Chats");
    // Setting up messaging on a relay also sets the Files tab's relay to it.
    chat_widget_->set_on_relay_chosen([this](const QString& server) {
        server_edit_->setText(server);
        save_server_setting();
    });
    // Something arrived while another tab was showing: say so on the Chats tab.
    chat_widget_->set_on_unread_changed([tabs, chats_tab](size_t unread) {
        tabs->setTabText(chats_tab, unread ? QString("Chats (%1)").arg(static_cast<qulonglong>(unread)) : QString("Chats"));
    });
    connect(tabs, &QTabWidget::currentChanged, this, [this](int) { chat_widget_->refresh_now(); });  // shown again: what was waiting is seen
}

MainWindow::~MainWindow() {
    // The Chats tab's worker thread uses the key store. Qt would delete the tab only after this
    // window's members (including the key store) are gone, so stop and delete it here, first.
    if (chat_widget_) {
        delete chat_widget_;
        chat_widget_ = nullptr;
    }
    engine_.cancel();
    if (worker_thread_.joinable()) worker_thread_.join();
    if (keystore_) keystore_->lock();  // wipe the decrypted keys from memory
}

// --- Key protection ---

std::string MainWindow::keychain_account() const {
    // One entry per identity, so several key folders on one computer don't collide.
    return "key-passphrase-" + keystore_->own_fingerprint().substr(0, 16);
}

void MainWindow::remember_passphrase(const std::string& passphrase) {
    if (!keychain::store(keychain_account(), passphrase)) {
        QMessageBox::warning(this, "Keychain",
                             "The passphrase could not be saved to your system's keychain (is a keyring "
                             "service running?). Your keys are still protected; you will be asked for the "
                             "passphrase each time you start the app.");
    }
}

// Runs before the window is shown: creates, validates and (if needed) unlocks the keys.
bool MainWindow::setup_keys(std::string& problem) {
    QSettings settings;

    if (!keystore_->keys_exist()) {
        auto choice = ask_new_passphrase(this, "Welcome to PQ File Transfer",
                                         protection_explanation("Let's set up your keys. Protect them with a passphrase?"),
                                         true);
        if (choice.outcome == DialogOutcome::Cancelled) {
            problem = "Setup was cancelled. Restart the app to set up your keys.";
            return false;
        }
        const bool protect = choice.outcome == DialogOutcome::Accepted;
        keystore_->initialize_keys(protect ? choice.passphrase : std::string());
        settings.setValue(KEY_PROTECTION_DECIDED, true);
        if (protect && choice.remember) remember_passphrase(choice.passphrase);
        return true;
    }

    keystore_->initialize_keys();  // validates the existing keys
    if (keystore_->private_keys_locked()) return unlock_keys(problem);

    // Keys from an earlier version are unprotected. Offer protection once; respect a "skip".
    if (!keystore_->private_keys_protected() && !settings.value(KEY_PROTECTION_DECIDED, false).toBool()) {
        auto choice = ask_new_passphrase(
            this, "Protect your keys?",
            protection_explanation("Your keys are currently stored on this computer without a passphrase. "
                                   "Protecting them doesn't change your fingerprint, so your contacts "
                                   "don't need to do anything."),
            true);
        if (choice.outcome == DialogOutcome::Accepted) {
            try {
                keystore_->set_passphrase(choice.passphrase);
            } catch (const std::exception& e) {
                QMessageBox::warning(this, "Key Protection", qstr(e.what()));
                return true;  // keys still work, just unprotected; ask again next time
            }
            settings.setValue(KEY_PROTECTION_DECIDED, true);
            if (choice.remember) remember_passphrase(choice.passphrase);
        } else if (choice.outcome == DialogOutcome::Skipped) {
            settings.setValue(KEY_PROTECTION_DECIDED, true);  // their choice; don't nag
        }
        // Cancelled (window closed): carry on unprotected and ask again next start.
    }
    return true;
}

bool MainWindow::unlock_keys(std::string& problem) {
    const std::string account = keychain_account();

    // The keychain first: this is what makes unlocking invisible on a normal day.
    if (auto saved = keychain::load(account)) {
        try {
            if (keystore_->unlock(*saved)) return true;
        } catch (const std::exception& e) {
            problem = e.what();
            return false;
        }
        keychain::remove(account);  // stale (e.g. the keys were replaced); fall through to asking
    }

    QString message = "Enter your passphrase to unlock your keys.";
    while (true) {
        auto choice = ask_existing_passphrase(this, "Unlock your keys", message, true);
        if (choice.outcome != DialogOutcome::Accepted) {
            problem = "Your keys are locked. Restart the app and enter your passphrase to continue.";
            return false;
        }
        try {
            if (keystore_->unlock(choice.passphrase)) {
                if (choice.remember) remember_passphrase(choice.passphrase);
                return true;
            }
        } catch (const std::exception& e) {
            problem = e.what();
            return false;
        }
        message = "That passphrase is wrong. Try again.";
    }
}

void MainWindow::update_key_status() {
    if (keystore_->private_keys_protected()) {
        key_status_label_->setText("Keys: protected by a passphrase");
        key_status_label_->setStyleSheet("color: #2e7d32;");
    } else {
        key_status_label_->setText("Keys: not protected by a passphrase");
        key_status_label_->setStyleSheet("color: #b26a00;");
    }
}

void MainWindow::set_passphrase_action() {
    auto choice = ask_new_passphrase(this, "Set a passphrase",
                                     protection_explanation("Protect your keys with a passphrase."), false);
    if (choice.outcome != DialogOutcome::Accepted) return;
    try {
        keystore_->set_passphrase(choice.passphrase);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    QSettings().setValue(KEY_PROTECTION_DECIDED, true);
    if (choice.remember) remember_passphrase(choice.passphrase);
    update_key_status();
    update_status("Your keys are now protected by a passphrase");
}

void MainWindow::change_passphrase_action() {
    auto current = ask_existing_passphrase(this, "Change passphrase", "Enter your current passphrase.", false, "Continue");
    if (current.outcome != DialogOutcome::Accepted) return;
    if (!keystore_->verify_passphrase(current.passphrase)) {
        QMessageBox::warning(this, "Change passphrase", "That passphrase is wrong.");
        return;
    }
    auto fresh = ask_new_passphrase(this, "Change passphrase", "Choose a new passphrase.", false);
    if (fresh.outcome != DialogOutcome::Accepted) return;
    try {
        keystore_->set_passphrase(fresh.passphrase);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    if (keychain::available()) {
        if (fresh.remember) remember_passphrase(fresh.passphrase);
        else keychain::remove(keychain_account());
    }
    update_key_status();
    update_status("Passphrase changed");
}

void MainWindow::remove_passphrase_action() {
    QMessageBox warn(QMessageBox::Warning, "Remove passphrase",
                     "Your private keys will be stored on this computer without protection. Anyone who "
                     "can copy your key files, for example from a stolen laptop or a backup, will be able "
                     "to read files sent to you.\n\nRemove the passphrase anyway?",
                     QMessageBox::Yes | QMessageBox::No, this);
    warn.setTextFormat(Qt::PlainText);
    warn.setDefaultButton(QMessageBox::No);
    if (warn.exec() != QMessageBox::Yes) return;

    auto current = ask_existing_passphrase(this, "Remove passphrase", "Enter your current passphrase to confirm.",
                                           false, "Remove");
    if (current.outcome != DialogOutcome::Accepted) return;
    if (!keystore_->verify_passphrase(current.passphrase)) {
        QMessageBox::warning(this, "Remove passphrase", "That passphrase is wrong.");
        return;
    }
    try {
        keystore_->remove_passphrase();
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    keychain::remove(keychain_account());
    QSettings().setValue(KEY_PROTECTION_DECIDED, true);
    update_key_status();
    update_status("The passphrase was removed. Your keys are stored without protection");
}

void MainWindow::forget_saved_passphrase() {
    keychain::remove(keychain_account());
    update_status("Saved passphrase removed. You will be asked for it next time you start the app");
}

// --- Contacts ---

void MainWindow::refresh_contacts() {
    QString previous = recipient_combo_->currentData().toString();
    recipient_combo_->clear();

    // Item data holds the contact name; an empty string means "send to myself".
    recipient_combo_->addItem("Myself (test)", QString());

    for (const auto& name : keystore_->list_contacts()) {
        auto contact = keystore_->load_contact(name);
        QString label = qstr(name);
        if (!contact) label += " (invalid keys)";
        else if (!contact->kem_verified) label += " (key not verified)";
        recipient_combo_->addItem(label, qstr(name));
        if (contact) {
            QString tip = "Fingerprint:\n" + formatted_fingerprint(contact->fingerprint);
            if (!contact->kem_verified)
                tip += "\n\nTheir encryption key is not verified. Ask them to send a new contact card "
                       "from the latest version.";
            recipient_combo_->setItemData(recipient_combo_->count() - 1, tip, Qt::ToolTipRole);
        }
    }

    int idx = recipient_combo_->findData(previous);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);
    if (chat_widget_) chat_widget_->refresh();
}

void MainWindow::add_contact() {
    QMessageBox choice(QMessageBox::Question, "Add Contact", "How would you like to add the contact?",
                       QMessageBox::NoButton, this);
    QAbstractButton* paste_button = choice.addButton("Paste contact card…", QMessageBox::AcceptRole);
    QAbstractButton* files_button = choice.addButton("Choose key files…", QMessageBox::AcceptRole);
    choice.addButton(QMessageBox::Cancel);
    choice.exec();

    if (choice.clickedButton() == paste_button) add_contact_from_card();
    else if (choice.clickedButton() == files_button) add_contact_from_files();
}

// Asks for a contact name, validates it, and confirms before replacing an existing contact.
std::optional<QString> MainWindow::ask_contact_name(const QString& suggested) {
    bool ok = false;
    QString name = QInputDialog::getText(this, "Add Contact",
                                         "Contact name (letters, digits, spaces, - _ .):",
                                         QLineEdit::Normal, suggested, &ok).trimmed();
    if (!ok || name.isEmpty()) return std::nullopt;

    std::string name_str = name.toStdString();
    if (!KeyStore::is_valid_contact_name(name_str)) {
        QMessageBox::warning(this, "Add Contact",
                             "Please use 1-64 letters, digits, spaces, '-', '_' or '.'. "
                             "The name can't start or end with a dot or space, or be \"self\".");
        return std::nullopt;
    }
    if (keystore_->contact_exists(name_str) &&
        QMessageBox::question(this, "Add Contact",
                              "A contact named \"" + name + "\" already exists.\n\n"
                              "If the keys you are adding differ from the saved ones, that is a key change: " + name +
                              " has a new identity, or this is someone else's card. You must check the new "
                              "fingerprint with them again before trusting it.\n\nReplace the saved keys?") !=
            QMessageBox::Yes) {
        return std::nullopt;
    }
    return name;
}

void MainWindow::add_contact_from_card() {
    // The box starts empty: the user pastes the card themselves (nothing is read from the clipboard unasked).
    bool ok = false;
    QString text = QInputDialog::getMultiLineText(this, "Add Contact",
                                                  "Paste the contact card you received:", QString(), &ok);
    if (!ok || text.trimmed().isEmpty()) return;

    std::string error;
    auto card = decode_any_contact_card(text.toStdString(), &error);
    if (!card) {
        QMessageBox::warning(this, "Add Contact", qstr(error));
        return;
    }

    if (card->bundle) {
        // A card from someone you already have is an update. Only the owner of the signing key
        // can make a valid newer one, so it is applied without asking.
        auto outcome = keystore_->import_bundle_for_known_identity(*card->bundle, card->send_token);
        using Result = KeyStore::BundleImportResult;
        if (outcome.result != Result::UnknownIdentity) {
            refresh_contacts();
            const QString who = qstr(outcome.contact_name);
            if (outcome.result == Result::Updated) {
                QString msg = "Updated " + who + "'s contact card.";
                if (outcome.was_unverified) msg += " Their encryption key is now verified.";
                if (card->bundle && card->bundle->has_mailbox() && !card->send_token.empty()) msg += " You can message them.";
                update_status(msg.toStdString());
                if (outcome.was_unverified && outcome.encryption_key_changed) {
                    QMessageBox warn(QMessageBox::Warning, "Encryption key replaced",
                                     "The encryption key you had saved for " + who + " did not match the key in "
                                     "their signed card, so it was replaced with the signed one.\n\nThe earlier "
                                     "card may have been altered on its way to you. If so, files you sent them "
                                     "before now could have been readable by someone else.",
                                     QMessageBox::Ok, this);
                    warn.setTextFormat(Qt::PlainText);
                    warn.exec();
                }
            } else if (outcome.result == Result::Unchanged) {
                update_status("You already have this contact card for " + who.toStdString());
            } else {
                QMessageBox::warning(this, "Add Contact",
                                     "This card for " + who + " is older than the one you have, and uses a "
                                     "different encryption key. It was ignored.");
            }
            return;
        }
    } else {
        QMessageBox old_card(QMessageBox::Warning, "Older contact card",
                             "This card comes from an older version of the app. It cannot prove that the "
                             "encryption key belongs to the person: someone who altered it on the way could "
                             "read the files you send, even if the fingerprint matches.\n\nAsk the sender to "
                             "update the app and send a new card. You can add them now, and they will be marked "
                             "\"encryption key not verified\" until you do.\n\nAdd them anyway?",
                             QMessageBox::Yes | QMessageBox::No, this);
        old_card.setTextFormat(Qt::PlainText);
        old_card.setDefaultButton(QMessageBox::No);
        if (old_card.exec() != QMessageBox::Yes) return;
    }

    auto name = ask_contact_name(qstr(sanitize_contact_name(card->name)));
    if (!name) return;
    finish_add_contact(*name, card->pub_kem, card->pub_dsa, card->server, card->bundle ? &*card->bundle : nullptr,
                       card->send_token);
}

void MainWindow::add_contact_from_files() {
    auto name = ask_contact_name(QString());
    if (!name) return;

    QString kem_path = QFileDialog::getOpenFileName(this, "Select " + *name + "'s ML-KEM public key (pq_public_kem.key)");
    if (kem_path.isEmpty()) return;
    QString dsa_path = QFileDialog::getOpenFileName(this, "Select " + *name + "'s ML-DSA public key (pq_public_dsa.key)");
    if (dsa_path.isEmpty()) return;

    auto pub_kem = read_small_file(kem_path, 64 * 1024);
    auto pub_dsa = read_small_file(dsa_path, 64 * 1024);
    const size_t kem_size = CryptoEngine::kem_public_key_size();
    const size_t dsa_size = CryptoEngine::sig_public_key_size();

    // The two key types have different sizes, so a swapped selection is fixable.
    if (pub_kem.size() == dsa_size && pub_dsa.size() == kem_size) std::swap(pub_kem, pub_dsa);
    if (pub_kem.size() != kem_size || pub_dsa.size() != dsa_size) {
        QMessageBox::warning(this, "Add Contact",
                             QString("Those files don't look like PQ File Transfer public keys "
                                     "(expected %1 and %2 bytes).").arg(static_cast<qulonglong>(kem_size)).arg(static_cast<qulonglong>(dsa_size)));
        return;
    }
    finish_add_contact(*name, pub_kem, pub_dsa, std::string(), nullptr);
}

// Shared by both ways of adding a contact: sanity checks, fingerprint confirmation, save.
void MainWindow::finish_add_contact(const QString& name,
                                    const std::vector<uint8_t>& pub_kem,
                                    const std::vector<uint8_t>& pub_dsa,
                                    const std::string& card_server,
                                    const IdentityBundle* bundle,
                                    const std::vector<uint8_t>& send_token) {
    std::string name_str = name.toStdString();
    std::string fp = CryptoEngine::fingerprint(pub_dsa);
    if (fp == keystore_->own_fingerprint()) {
        QMessageBox::warning(this, "Add Contact", "These are your own public keys.");
        return;
    }
    if (auto existing = keystore_->find_contact_by_fingerprint(fp); existing && existing->name != name_str) {
        QMessageBox::warning(this, "Add Contact",
                             "These keys are already saved as \"" + qstr(existing->name) + "\".");
        return;
    }

    const QString risk = bundle
        ? "This card is signed, so its keys can't be altered on the way without being noticed. A signature "
          "can't say who made the card, though. If someone else made it, they could read the files you send "
          "and pretend to be " + name + "."
        : "A contact card or key files can be swapped on the way to you. If that happened, the sender could "
          "read the files you send and pretend to be " + name + ". This one has no signature on its encryption "
          "key, so it will be marked \"encryption key not verified\".";
    QMessageBox confirm(QMessageBox::Question, "Verify Fingerprint",
                        "Before trusting these keys, confirm with " + name +
                        " over a channel you trust (in person, or a phone or video call where you "
                        "recognise them) that their fingerprint is:\n\n" + formatted_fingerprint(fp) +
                        "\n\n" + risk + "\n\nDoes the fingerprint match?",
                        QMessageBox::Yes | QMessageBox::No, this);
    confirm.setTextFormat(Qt::PlainText);
    if (confirm.exec() != QMessageBox::Yes) return;

    try {
        if (bundle) {
            keystore_->save_contact_bundle(name_str, *bundle);
            if (send_token.size() == 32) keystore_->save_contact_token(name_str, send_token);
        } else {
            keystore_->save_contact(name_str, pub_kem, pub_dsa);
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Add Contact", qstr(e.what()));
        return;
    }

    // The user confirmed the fingerprint above, so they count as verified in the chats too.
    if (chat_widget_) chat_widget_->mark_verified(fp);
    refresh_contacts();
    int idx = recipient_combo_->findData(name);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);
    update_status("Contact added: " + name_str);

    // The card may suggest a relay server. Never switch silently: a card can come from anyone.
    if (auto suggested = parse_server_address(card_server)) {
        auto current = configured_server(server_edit_);
        if (!current || !same_server(*current, *suggested)) {
            QMessageBox ask(QMessageBox::Question, "Relay Server",
                            name + "'s card suggests this relay server:\n\n" + qstr(format_server_address(*suggested)) +
                            "\n\nYour current setting is:\n\n" +
                            (current ? qstr(format_server_address(*current)) : server_edit_->text()) +
                            "\n\nSwitch to the suggested server? Only do this if you recognise it.",
                            QMessageBox::Yes | QMessageBox::No, this);
            ask.setTextFormat(Qt::PlainText);
            if (ask.exec() == QMessageBox::Yes) {
                server_edit_->setText(qstr(format_server_address(*suggested)));
                save_server_setting();
            }
        }
    }
}

void MainWindow::remove_contact() {
    QString name = recipient_combo_->currentData().toString();
    if (name.isEmpty()) return;  // "Myself"
    if (QMessageBox::question(this, "Remove Contact", "Remove " + name + " and their keys?") != QMessageBox::Yes)
        return;
    try {
        keystore_->delete_contact(name.toStdString());
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Remove Contact", qstr(e.what()));
        return;
    }
    refresh_contacts();
    update_status("Contact removed: " + name.toStdString());
}

void MainWindow::copy_contact_card() {
    // With messaging set up, every card carries a fresh permission to message you, made for one person.
    if (chat_widget_ && chat_widget_->is_set_up()) {
        chat_widget_->copy_card_to_clipboard();
        return;
    }
    QSettings settings;
    bool ok = false;
    QString name = QInputDialog::getText(this, "Contact Card", "Your name, as your contacts will see it:",
                                         QLineEdit::Normal,
                                         settings.value("display_name", default_display_name()).toString(), &ok).trimmed();
    if (!ok || name.isEmpty()) return;
    if (name.toUtf8().size() > 64) {
        QMessageBox::warning(this, "Contact Card", "Please use a shorter name (64 bytes at most).");
        return;
    }
    settings.setValue("display_name", name);

    std::string relay_hint;
    if (auto server = configured_server(server_edit_)) relay_hint = format_server_address(*server);

    std::vector<uint8_t> bundle;
    try {
        bundle = keystore_->make_own_bundle(name.toStdString(), relay_hint);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Contact Card", qstr(e.what()));
        return;
    }
    QGuiApplication::clipboard()->setText(qstr(encode_contact_card_v2(bundle)));

    QMessageBox info(QMessageBox::Information, "Contact Card",
                     "Your contact card is on the clipboard. Paste it into a message to your contact.\n\n"
                     "It contains only public information, and it is signed with your identity key, so it "
                     "can't be altered on the way without being noticed. A signature can't say who made a "
                     "card, though, so ask your contact to check this fingerprint with you in person or on a "
                     "call when they add you:\n\n" +
                     formatted_fingerprint(keystore_->own_fingerprint()),
                     QMessageBox::Ok, this);
    info.setTextFormat(Qt::PlainText);
    info.exec();
    update_status("Contact card copied to clipboard");
}

void MainWindow::export_keys() {
    QString dir = QFileDialog::getExistingDirectory(this, "Choose a folder for your public keys");
    if (dir.isEmpty()) return;
    try {
        keystore_->export_public_keys(std::filesystem::u8path(dir.toStdString()));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Export Keys", qstr(e.what()));
        return;
    }
    QMessageBox info(QMessageBox::Information, "Export Keys",
                     "Saved pq_public_kem.key and pq_public_dsa.key to:\n" + dir +
                     "\n\nThese are public and safe to send by email or chat. Ask your contact to "
                     "check this fingerprint with you when they add you:\n\n" +
                     formatted_fingerprint(keystore_->own_fingerprint()),
                     QMessageBox::Ok, this);
    info.setTextFormat(Qt::PlainText);
    info.exec();
}

// --- Transfers ---

void MainWindow::save_server_setting() {
    QSettings().setValue(SERVER_SETTING, server_edit_->text().trimmed());
}

void MainWindow::start_send() {
    if (busy_) return;

    auto server = configured_server(server_edit_);
    if (!server) {
        QMessageBox::warning(this, "Send File", "Enter the relay server as host or host:port.");
        return;
    }
    const std::string host = server->host;
    const uint16_t port = server->port;

    QString contact_name = recipient_combo_->currentData().toString();
    std::optional<KeyStore::Contact> recipient =
        contact_name.isEmpty() ? std::optional<KeyStore::Contact>(keystore_->self_contact())
                               : keystore_->load_contact(contact_name.toStdString());
    if (!recipient) {
        QMessageBox::warning(this, "Send File", "The keys for " + contact_name + " are missing or invalid.");
        return;
    }
    if (!recipient->kem_verified) {
        QMessageBox warn(QMessageBox::Warning, "Encryption key not verified",
                         contact_name + "'s encryption key came from an older card or from key files, so nothing "
                         "proves it is really theirs. If it was altered on the way to you, whoever did it could "
                         "read this file.\n\nAsk " + contact_name + " to update the app and send you a new "
                         "contact card, then add it with +.\n\nSend anyway?",
                         QMessageBox::Yes | QMessageBox::No, this);
        warn.setTextFormat(Qt::PlainText);
        warn.setDefaultButton(QMessageBox::No);
        if (warn.exec() != QMessageBox::Yes) return;
    }

    QString filepath = QFileDialog::getOpenFileName(this, "Select File to Send");
    if (filepath.isEmpty()) return;

    save_server_setting();
    last_server_ = *server;
    progress_bar_->setValue(0);
    transfer_id_label_->clear();
    current_transfer_id_.clear();
    current_share_link_.clear();
    copy_link_button_->setEnabled(false);
    copy_id_button_->setEnabled(false);

    run_in_background([this, path = filepath.toStdString(), host, port, contact = *recipient] {
        engine_.upload_file(path, host, port, contact);
    });
}

void MainWindow::start_receive() {
    if (busy_) return;

    auto server = configured_server(server_edit_);
    if (!server) {
        QMessageBox::warning(this, "Receive File", "Enter the relay server as host or host:port.");
        return;
    }
    std::string host = server->host;
    uint16_t port = server->port;

    bool ok = false;
    QString input = QInputDialog::getText(this, "Receive File", "Paste the share link or transfer ID:",
                                          QLineEdit::Normal, "", &ok).trimmed();
    if (!ok || input.isEmpty()) return;

    std::string id = input.toStdString();
    if (input.startsWith("pqft://", Qt::CaseInsensitive)) {
        auto link = parse_share_link(id);
        if (!link) {
            QMessageBox::warning(this, "Receive File", "That share link isn't valid. Check that it was copied completely.");
            return;
        }
        id = link->transfer_id;

        // A link names its own relay. It can come from anyone, so ask before using it.
        if (!same_server(link->server, *server)) {
            QMessageBox box(QMessageBox::Question, "Relay Server",
                            "This link uses a different relay server than the one you have set.\n\n"
                            "Link:  " + qstr(format_server_address(link->server)) +
                            "\nYours: " + qstr(format_server_address(*server)) +
                            "\n\nWhich should be used for this download?",
                            QMessageBox::NoButton, this);
            box.setTextFormat(Qt::PlainText);
            QAbstractButton* use_link = box.addButton("Use the link's server", QMessageBox::AcceptRole);
            QAbstractButton* use_mine = box.addButton("Use my server", QMessageBox::AcceptRole);
            box.addButton(QMessageBox::Cancel);
            box.exec();
            if (box.clickedButton() == use_link) {
                host = link->server.host;
                port = link->server.port;
            } else if (box.clickedButton() != use_mine) {
                return;
            }
        }
    }

    save_server_setting();
    progress_bar_->setValue(0);
    transfer_id_label_->setText("Receiving: " + qstr(id));
    copy_link_button_->setEnabled(false);
    copy_id_button_->setEnabled(false);

    std::string output_dir = keystore_->downloads_dir().u8string();
    run_in_background([this, id, host, port, output_dir] {
        engine_.download_file(id, host, port, output_dir);
    });
}

void MainWindow::run_in_background(std::function<void()> job) {
    if (worker_thread_.joinable()) worker_thread_.join();  // previous job has finished
    set_busy(true);
    update_status("Working...");

    worker_thread_ = std::thread([this, job = std::move(job)] {
        try {
            job();
        } catch (const std::exception& e) {
            QMetaObject::invokeMethod(this, [this, msg = std::string(e.what())] { show_error(msg); });
        } catch (...) {
            QMetaObject::invokeMethod(this, [this] { show_error("Unexpected error"); });
        }
        QMetaObject::invokeMethod(this, [this] { set_busy(false); });
    });
}

void MainWindow::set_busy(bool busy) {
    busy_ = busy;
    send_button_->setEnabled(!busy);
    receive_button_->setEnabled(!busy);
    add_contact_button_->setEnabled(!busy);
    remove_contact_button_->setEnabled(!busy);
    key_protection_button_->setEnabled(!busy);
    copy_card_button_->setEnabled(!busy);
    export_keys_button_->setEnabled(!busy);
    server_edit_->setEnabled(!busy);
    recipient_combo_->setEnabled(!busy);
    cancel_button_->setEnabled(busy);
}

void MainWindow::copy_share_link() {
    if (current_share_link_.isEmpty()) return;
    QGuiApplication::clipboard()->setText(current_share_link_);
    update_status("Share link copied to clipboard");
}

void MainWindow::copy_transfer_id() {
    if (current_transfer_id_.isEmpty()) return;
    QGuiApplication::clipboard()->setText(current_transfer_id_);
    update_status("Transfer ID copied to clipboard");
}

void MainWindow::open_downloads() {
    QString dir = qstr(keystore_->downloads_dir().u8string());
    QDir().mkpath(dir);
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

// --- Display ---

void MainWindow::update_status(const std::string& msg) {
    status_label_->setText("Status: " + qstr(msg));
    status_label_->setStyleSheet("");
}

void MainWindow::update_progress(double fraction) {
    if (progress_bar_) progress_bar_->setValue(static_cast<int>(std::clamp(fraction, 0.0, 1.0) * 100));
}

void MainWindow::show_error(const std::string& error) {
    status_label_->setText("Error: " + qstr(error));
    status_label_->setStyleSheet("color: #c62828;");
    if (progress_bar_) progress_bar_->setValue(0);
}

void MainWindow::show_complete(const std::string& filepath) {
    // The engine's last status message already says what happened.
    status_label_->setToolTip(qstr(filepath));
    status_label_->setStyleSheet("color: #2e7d32;");
    if (progress_bar_) progress_bar_->setValue(100);
}

void MainWindow::show_transfer_id(const std::string& id) {
    current_transfer_id_ = qstr(id);
    current_share_link_ = qstr(build_share_link(last_server_, id));
    transfer_id_label_->setText("Share link: " + current_share_link_ +
                                "\nSend this to the recipient. It works once and expires in 24 hours.");
    copy_link_button_->setEnabled(true);
    copy_id_button_->setEnabled(true);
}
