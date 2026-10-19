#include "main_window.h"
#include "crypto_engine.h"

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
#include <QMessageBox>
#include <QMetaObject>
#include <QProgressBar>
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

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* layout = new QVBoxLayout(central);

    auto* title = new QLabel("PQ File Transfer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size: 18px; font-weight: bold;");
    layout->addWidget(title);

    status_label_ = plain_label("Status: Ready", this);

    try {
        keystore_ = std::make_unique<KeyStore>();
        keystore_->initialize_keys();
    } catch (const std::exception& e) {
        keystore_.reset();
        layout->addWidget(status_label_);
        layout->addStretch();
        show_error(std::string("Key setup failed: ") + e.what());
        return;
    }

    // --- Identity ---
    layout->addWidget(plain_label("Your fingerprint. Contacts should check it with you before trusting your keys:", this));
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
}

MainWindow::~MainWindow() {
    engine_.cancel();
    if (worker_thread_.joinable()) worker_thread_.join();
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
        recipient_combo_->addItem(label, qstr(name));
        if (contact) {
            recipient_combo_->setItemData(recipient_combo_->count() - 1,
                                          "Fingerprint:\n" + formatted_fingerprint(contact->fingerprint),
                                          Qt::ToolTipRole);
        }
    }

    int idx = recipient_combo_->findData(previous);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);
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
        QMessageBox::question(this, "Add Contact", "A contact named \"" + name + "\" already exists. Replace their keys?") !=
            QMessageBox::Yes) {
        return std::nullopt;
    }
    return name;
}

void MainWindow::add_contact_from_card() {
    // If a card is already on the clipboard, save the user a paste.
    QString clip = QGuiApplication::clipboard()->text();
    QString initial = looks_like_contact_card(clip.toStdString()) ? clip : QString();

    bool ok = false;
    QString text = QInputDialog::getMultiLineText(this, "Add Contact",
                                                  "Paste the contact card you received:", initial, &ok);
    if (!ok || text.trimmed().isEmpty()) return;

    std::string error;
    auto card = decode_contact_card(text.toStdString(), &error);
    if (!card) {
        QMessageBox::warning(this, "Add Contact", qstr(error));
        return;
    }

    auto name = ask_contact_name(qstr(sanitize_contact_name(card->name)));
    if (!name) return;
    finish_add_contact(*name, card->pub_kem, card->pub_dsa, card->server);
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
    finish_add_contact(*name, pub_kem, pub_dsa, std::string());
}

// Shared by both ways of adding a contact: sanity checks, fingerprint confirmation, save.
void MainWindow::finish_add_contact(const QString& name,
                                    const std::vector<uint8_t>& pub_kem,
                                    const std::vector<uint8_t>& pub_dsa,
                                    const std::string& card_server) {
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

    QMessageBox confirm(QMessageBox::Question, "Verify Fingerprint",
                        "Before trusting these keys, confirm with " + name +
                        " over a channel you trust (in person, or a phone or video call where you "
                        "recognise them) that their fingerprint is:\n\n" + formatted_fingerprint(fp) +
                        "\n\nA contact card or key files can be swapped on the way to you. If that "
                        "happened, the sender could read the files you send and pretend to be " + name +
                        ".\n\nDoes the fingerprint match?",
                        QMessageBox::Yes | QMessageBox::No, this);
    confirm.setTextFormat(Qt::PlainText);
    if (confirm.exec() != QMessageBox::Yes) return;

    try {
        keystore_->save_contact(name_str, pub_kem, pub_dsa);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Add Contact", qstr(e.what()));
        return;
    }

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

    ContactCard card;
    card.name = name.toStdString();
    card.pub_kem = keystore_->load_public_kem();
    card.pub_dsa = keystore_->load_public_dsa();
    if (card.pub_kem.empty() || card.pub_dsa.empty()) {
        QMessageBox::warning(this, "Contact Card", "Your public keys could not be read.");
        return;
    }
    if (auto server = configured_server(server_edit_)) card.server = format_server_address(*server);

    QGuiApplication::clipboard()->setText(qstr(encode_contact_card(card)));

    QMessageBox info(QMessageBox::Information, "Contact Card",
                     "Your contact card is on the clipboard. Paste it into a message to your contact.\n\n"
                     "It contains only public information. Because anyone could have made a card, ask your "
                     "contact to check this fingerprint with you in person or on a call when they add you:\n\n" +
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
