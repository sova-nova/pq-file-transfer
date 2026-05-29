#include "main_window.h"
#include "key_store.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QMetaObject>
#include <QLineEdit>
#include <fstream>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("PQ File Transfer");
    setMinimumSize(450, 450);

    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);

    // Title
    auto* title = new QLabel("PQ File Transfer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size: 18px; font-weight: bold;");
    layout->addWidget(title);

    // Initialize keys
    KeyStore keystore;
    try {
        keystore.initialize_keys();
    } catch (const std::exception& e) {
        status_label_ = new QLabel("Key init failed: " + QString(e.what()), this);
        status_label_->setStyleSheet("color: red;");
        layout->addWidget(status_label_);
        return;
    }

    // Fingerprint
    auto pub_dsa = keystore.load_public_dsa();
    QString fingerprint;
    for (size_t i = 0; i < 8 && i < pub_dsa.size(); i++) {
        fingerprint += QString("%1").arg(pub_dsa[i], 2, 16, QChar('0'));
        if (i < 7) fingerprint += ":";
    }

    auto* fp_label = new QLabel("Your fingerprint: " + fingerprint, this);
    fp_label->setAlignment(Qt::AlignCenter);
    fp_label->setStyleSheet("font-size: 11px; color: #555; font-family: monospace;");
    fp_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(fp_label);

    layout->addSpacing(10);

    // Recipient selector
    auto* recipient_layout = new QHBoxLayout();
    auto* recipient_label = new QLabel("Send to:", this);
    recipient_combo_ = new QComboBox(this);
    recipient_combo_->setMinimumWidth(150);
    recipient_layout->addWidget(recipient_label);
    recipient_layout->addWidget(recipient_combo_, 1);

    add_contact_button_ = new QPushButton("+", this);
    add_contact_button_->setMaximumWidth(30);
    recipient_layout->addWidget(add_contact_button_);

    layout->addLayout(recipient_layout);

    // Buttons
    send_button_ = new QPushButton("Send File", this);
    receive_button_ = new QPushButton("Receive File", this);
    send_button_->setMinimumHeight(40);
    receive_button_->setMinimumHeight(40);

    layout->addWidget(send_button_);
    layout->addWidget(receive_button_);

    layout->addSpacing(10);

    // Progress bar
    progress_bar_ = new QProgressBar(this);
    progress_bar_->setRange(0, 100);
    progress_bar_->setValue(0);
    progress_bar_->setTextVisible(true);
    layout->addWidget(progress_bar_);

    // Transfer ID display
    transfer_id_label_ = new QLabel("", this);
    transfer_id_label_->setAlignment(Qt::AlignCenter);
    transfer_id_label_->setStyleSheet("font-size: 12px; color: #666;");
    transfer_id_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(transfer_id_label_);

    layout->addStretch();

    // Status bar
    status_label_ = new QLabel("Status: Ready", this);
    status_label_->setStyleSheet("color: gray;");
    layout->addWidget(status_label_);

    // Load contacts
    refresh_contacts();

    // Wire up callbacks
    engine_.on_status = [this](const std::string& msg) {
        QMetaObject::invokeMethod(this, [this, msg]() { update_status(msg); });
    };

    engine_.on_progress = [this](double percent) {
        QMetaObject::invokeMethod(this, [this, percent]() { update_progress(percent); });
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

    // Button connections
    connect(send_button_, &QPushButton::clicked, this, &MainWindow::start_send);
    connect(receive_button_, &QPushButton::clicked, this, &MainWindow::start_receive);
    connect(add_contact_button_, &QPushButton::clicked, this, &MainWindow::add_contact);
}

MainWindow::~MainWindow() {
    engine_.cancel();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void MainWindow::refresh_contacts() {
    recipient_combo_->clear();

    KeyStore keystore;
    auto contacts = keystore.list_contacts();

    // Add "self" as an option for testing
    recipient_combo_->addItem("self");

    for (const auto& name : contacts) {
        recipient_combo_->addItem(QString::fromStdString(name));
    }
}

void MainWindow::add_contact() {
    QString name = QInputDialog::getText(this, "Add Contact", "Contact name:");
    if (name.isEmpty()) return;

    QString kem_path = QFileDialog::getOpenFileName(
        this, "Select Contact's ML-KEM-768 Public Key");
    if (kem_path.isEmpty()) return;

    QString dsa_path = QFileDialog::getOpenFileName(
        this, "Select Contact's ML-DSA-65 Public Key");
    if (dsa_path.isEmpty()) return;

    // Read the key files
    auto read_file = [](const QString& path) -> std::vector<uint8_t> {
        std::ifstream f(path.toStdString(), std::ios::binary | std::ios::ate);
        if (!f.is_open()) return {};
        auto size = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> data(size);
        f.read(reinterpret_cast<char*>(data.data()), size);
        return data;
    };

    auto pub_kem = read_file(kem_path);
    auto pub_dsa = read_file(dsa_path);

    if (pub_kem.empty() || pub_dsa.empty()) {
        QMessageBox::warning(this, "Error", "Failed to read key files");
        return;
    }

    KeyStore keystore;
    keystore.save_contact(name.toStdString(), pub_kem, pub_dsa);

    refresh_contacts();

    // Select the newly added contact
    int idx = recipient_combo_->findText(name);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);

    update_status("Contact added: " + name.toStdString());
}

void MainWindow::start_send() {
    QString filepath = QFileDialog::getOpenFileName(this, "Select File to Send");
    if (filepath.isEmpty()) return;

    QString recipient = recipient_combo_->currentText();
    if (recipient.isEmpty()) {
        QMessageBox::warning(this, "Error", "Select a recipient first");
        return;
    }

    set_buttons_enabled(false);
    progress_bar_->setValue(0);
    transfer_id_label_->setText("");
    update_status("Preparing to send...");

    if (worker_thread_.joinable()) worker_thread_.join();

    std::string recipient_str;
    if (recipient == "self") {
        // Self-test: load own keys as a "contact" named by our fingerprint
        KeyStore ks;
        auto pub_dsa = ks.load_public_dsa();
        std::string fp;
        for (size_t i = 0; i < 8 && i < pub_dsa.size(); i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", pub_dsa[i]);
            fp += hex;
        }
        // Save own keys as a contact if not already there
        auto existing = ks.load_contact(fp);
        if (existing.pub_kem.empty()) {
            ks.save_contact(fp, ks.load_public_kem(), pub_dsa);
        }
        recipient_str = fp;
    } else {
        recipient_str = recipient.toStdString();
    }

    worker_thread_ = std::thread([this, filepath = filepath.toStdString(),
                                   recipient_str]() {
        try {
            engine_.upload_file(filepath, "10.0.0.248", 9000, recipient_str);
        } catch (const std::exception& e) {
            QMetaObject::invokeMethod(this, [this, msg = std::string(e.what())]() {
                show_error(msg);
            });
        }
        QMetaObject::invokeMethod(this, [this]() { set_buttons_enabled(true); });
    });
}

void MainWindow::start_receive() {
    QString transfer_id = QInputDialog::getText(
        this, "Receive File", "Enter Transfer ID:");
    if (transfer_id.isEmpty()) return;

    set_buttons_enabled(false);
    progress_bar_->setValue(0);
    transfer_id_label_->setText("Downloading: " + transfer_id);
    update_status("Preparing to receive...");

    if (worker_thread_.joinable()) worker_thread_.join();

    std::string output_dir = QDir::homePath().toStdString() + "/.pq-file-transfer/downloads";

    worker_thread_ = std::thread([this, id = transfer_id.toStdString(), output_dir]() {
        try {
            engine_.download_file(id, "10.0.0.248", 9000, output_dir);
        } catch (const std::exception& e) {
            QMetaObject::invokeMethod(this, [this, msg = std::string(e.what())]() {
                show_error(msg);
            });
        }
        QMetaObject::invokeMethod(this, [this]() { set_buttons_enabled(true); });
    });
}

void MainWindow::set_buttons_enabled(bool enabled) {
    send_button_->setEnabled(enabled);
    receive_button_->setEnabled(enabled);
    add_contact_button_->setEnabled(enabled);
}

void MainWindow::update_status(const std::string& msg) {
    status_label_->setText("Status: " + QString::fromStdString(msg));
    status_label_->setStyleSheet("color: black;");
}

void MainWindow::update_progress(double percent) {
    progress_bar_->setValue(static_cast<int>(percent * 100));
}

void MainWindow::show_error(const std::string& error) {
    status_label_->setText("Error: " + QString::fromStdString(error));
    status_label_->setStyleSheet("color: red;");
    progress_bar_->setValue(0);
}

void MainWindow::show_complete(const std::string& filepath) {
    status_label_->setText("Complete: " + QString::fromStdString(filepath));
    status_label_->setStyleSheet("color: green;");
    progress_bar_->setValue(100);
}

void MainWindow::show_transfer_id(const std::string& id) {
    transfer_id_label_->setText("Transfer ID: " + QString::fromStdString(id));
}