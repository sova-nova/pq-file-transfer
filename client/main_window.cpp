#include "main_window.h"
#include "key_store.h"
#include <QVBoxLayout>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QMetaObject>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("PQ File Transfer");
    setMinimumSize(450, 400);

    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);

    // Title
    auto* title = new QLabel("PQ File Transfer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size: 18px; font-weight: bold;");
    layout->addWidget(title);

    // Initialize keys on startup
    KeyStore keystore;
    try {
        keystore.initialize_keys();
    } catch (const std::exception& e) {
        status_label_ = new QLabel("Key init failed: " + QString(e.what()), this);
        status_label_->setStyleSheet("color: red;");
        layout->addWidget(status_label_);
        return;
    }

    // Show fingerprint (first 8 bytes of DSA public key, hex-encoded)
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
}

MainWindow::~MainWindow() {
    engine_.cancel();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void MainWindow::start_send() {
    QString filepath = QFileDialog::getOpenFileName(this, "Select File to Send");
    if (filepath.isEmpty()) return;

    set_buttons_enabled(false);
    progress_bar_->setValue(0);
    transfer_id_label_->setText("");
    update_status("Preparing to send...");

    if (worker_thread_.joinable()) worker_thread_.join();

    worker_thread_ = std::thread([this, filepath = filepath.toStdString()]() {
        engine_.upload_file(filepath, "127.0.0.1", 9000);
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
        engine_.download_file(id, "127.0.0.1", 9000, output_dir);
        QMetaObject::invokeMethod(this, [this]() { set_buttons_enabled(true); });
    });
}

void MainWindow::set_buttons_enabled(bool enabled) {
    send_button_->setEnabled(enabled);
    receive_button_->setEnabled(enabled);
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