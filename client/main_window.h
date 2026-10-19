#pragma once

#include <QMainWindow>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "key_store.h"
#include "transfer_engine.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    QLabel* status_label_ = nullptr;
    QLabel* fingerprint_label_ = nullptr;
    QLineEdit* server_edit_ = nullptr;
    QComboBox* recipient_combo_ = nullptr;
    QPushButton* add_contact_button_ = nullptr;
    QPushButton* remove_contact_button_ = nullptr;
    QPushButton* export_keys_button_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QPushButton* receive_button_ = nullptr;
    QPushButton* cancel_button_ = nullptr;
    QPushButton* copy_id_button_ = nullptr;
    QPushButton* open_downloads_button_ = nullptr;
    QProgressBar* progress_bar_ = nullptr;
    QLabel* transfer_id_label_ = nullptr;

    std::unique_ptr<KeyStore> keystore_;
    TransferEngine engine_;
    std::thread worker_thread_;
    std::atomic<bool> busy_{false};
    QString current_transfer_id_;

    void start_send();
    void start_receive();
    void add_contact();
    void remove_contact();
    void export_keys();
    void copy_transfer_id();
    void open_downloads();
    void refresh_contacts();
    void save_server_setting();

    void run_in_background(std::function<void()> job);
    void set_busy(bool busy);

    void update_status(const std::string& msg);
    void update_progress(double fraction);
    void show_error(const std::string& error);
    void show_complete(const std::string& filepath);
    void show_transfer_id(const std::string& id);
};
