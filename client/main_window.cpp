#include "main_window.h"
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("PQ File Transfer");
    setMinimumSize(400, 300);

    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);

    // Title
    auto* title = new QLabel("PQ File Transfer", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size: 18px; font-weight: bold;");
    layout->addWidget(title);

    layout->addSpacing(20);

    // Buttons
    send_button_ = new QPushButton("Send File", this);
    receive_button_ = new QPushButton("Receive File", this);
    send_button_->setMinimumHeight(40);
    receive_button_->setMinimumHeight(40);

    layout->addWidget(send_button_);
    layout->addWidget(receive_button_);

    layout->addStretch();

    // Status bar at bottom
    status_label_ = new QLabel("Status: Ready", this);
    status_label_->setStyleSheet("color: gray;");
    layout->addWidget(status_label_);

    // Placeholder connections — will be wired up in later phases
    connect(send_button_, &QPushButton::clicked, this, [this]() {
        status_label_->setText("Status: Send not yet implemented");
        status_label_->setStyleSheet("color: orange;");
    });

    connect(receive_button_, &QPushButton::clicked, this, [this]() {
        status_label_->setText("Status: Receive not yet implemented");
        status_label_->setStyleSheet("color: orange;");
    });
}