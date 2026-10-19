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

constexpr uint16_t DEFAULT_PORT = 9000;
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

// Accepts "host", "host:port", "[ipv6]" or "[ipv6]:port".
bool parse_server_address(const QString& text, std::string& host, uint16_t& port) {
    QString s = text.trimmed();
    QString h, p;
    if (s.startsWith('[')) {
        int end = s.indexOf(']');
        if (end < 0) return false;
        h = s.mid(1, end - 1);
        QString rest = s.mid(end + 1);
        if (!rest.isEmpty()) {
            if (!rest.startsWith(':')) return false;
            p = rest.mid(1);
        }
    } else if (s.count(':') == 1) {
        int colon = s.indexOf(':');
        h = s.left(colon);
        p = s.mid(colon + 1);
    } else {
        h = s;  // plain host, or a bare IPv6 address without a port
    }
    if (h.isEmpty()) return false;

    port = DEFAULT_PORT;
    if (!p.isEmpty()) {
        bool ok = false;
        uint value = p.toUInt(&ok);
        if (!ok || value == 0 || value > 65535) return false;
        port = static_cast<uint16_t>(value);
    }
    host = h.toStdString();
    return true;
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

    export_keys_button_ = new QPushButton("Export My Public Keys…", this);
    layout->addWidget(export_keys_button_);
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
    copy_id_button_ = new QPushButton("Copy Transfer ID", this);
    copy_id_button_->setEnabled(false);
    open_downloads_button_ = new QPushButton("Open Downloads", this);
    util_layout->addWidget(copy_id_button_);
    util_layout->addWidget(open_downloads_button_);
    layout->addLayout(util_layout);

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
    connect(export_keys_button_, &QPushButton::clicked, this, &MainWindow::export_keys);
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
    bool ok = false;
    QString name = QInputDialog::getText(this, "Add Contact",
                                         "Contact name (letters, digits, spaces, - _ .):",
                                         QLineEdit::Normal, "", &ok).trimmed();
    if (!ok || name.isEmpty()) return;

    std::string name_str = name.toStdString();
    if (!KeyStore::is_valid_contact_name(name_str)) {
        QMessageBox::warning(this, "Add Contact",
                             "Please use 1-64 letters, digits, spaces, '-', '_' or '.'. "
                             "The name can't start or end with a dot or space, or be \"self\".");
        return;
    }
    if (keystore_->contact_exists(name_str) &&
        QMessageBox::question(this, "Add Contact", "A contact named \"" + name + "\" already exists. Replace their keys?") !=
            QMessageBox::Yes) {
        return;
    }

    QString kem_path = QFileDialog::getOpenFileName(this, "Select " + name + "'s ML-KEM public key (pq_public_kem.key)");
    if (kem_path.isEmpty()) return;
    QString dsa_path = QFileDialog::getOpenFileName(this, "Select " + name + "'s ML-DSA public key (pq_public_dsa.key)");
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
                        "\n\nIf someone swapped these files on the way to you, they could read the "
                        "files you send and pretend to be " + name + ".\n\nDoes the fingerprint match?",
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

    std::string host;
    uint16_t port = 0;
    if (!parse_server_address(server_edit_->text(), host, port)) {
        QMessageBox::warning(this, "Send File", "Enter the relay server as host or host:port.");
        return;
    }

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
    progress_bar_->setValue(0);
    transfer_id_label_->clear();
    current_transfer_id_.clear();
    copy_id_button_->setEnabled(false);

    run_in_background([this, path = filepath.toStdString(), host, port, contact = *recipient] {
        engine_.upload_file(path, host, port, contact);
    });
}

void MainWindow::start_receive() {
    if (busy_) return;

    std::string host;
    uint16_t port = 0;
    if (!parse_server_address(server_edit_->text(), host, port)) {
        QMessageBox::warning(this, "Receive File", "Enter the relay server as host or host:port.");
        return;
    }

    bool ok = false;
    QString transfer_id = QInputDialog::getText(this, "Receive File", "Transfer ID:",
                                                QLineEdit::Normal, "", &ok).trimmed();
    if (!ok || transfer_id.isEmpty()) return;

    save_server_setting();
    progress_bar_->setValue(0);
    transfer_id_label_->setText("Receiving: " + transfer_id);
    copy_id_button_->setEnabled(false);

    std::string output_dir = keystore_->downloads_dir().u8string();
    run_in_background([this, id = transfer_id.toStdString(), host, port, output_dir] {
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
    export_keys_button_->setEnabled(!busy);
    server_edit_->setEnabled(!busy);
    recipient_combo_->setEnabled(!busy);
    cancel_button_->setEnabled(busy);
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
    transfer_id_label_->setText("Transfer ID: " + current_transfer_id_ +
                                "\nSend this to the recipient. It works once and expires in 24 hours.");
    copy_id_button_->setEnabled(true);
}
