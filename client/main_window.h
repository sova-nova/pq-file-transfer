#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <string>
#include <thread>
#include <atomic>

#include "transfer_engine.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private:
    QLabel* status_label_;
    QPushButton* send_button_;
    QPushButton* receive_button_;
    QProgressBar* progress_bar_;
    QLabel* transfer_id_label_;

    TransferEngine engine_;
    std::thread worker_thread_;
    std::atomic<bool> running_{false};

    void start_send();
    void start_receive();
    void set_buttons_enabled(bool enabled);

    // Thread-safe UI updates
    void update_status(const std::string& msg);
    void update_progress(double percent);
    void show_error(const std::string& error);
    void show_complete(const std::string& filepath);
    void show_transfer_id(const std::string& id);
};