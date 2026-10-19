#pragma once

#include <QMainWindow>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "key_store.h"
#include "sharing.h"
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
    QLabel* key_status_label_ = nullptr;
    QPushButton* key_protection_button_ = nullptr;
    QPushButton* copy_card_button_ = nullptr;
    QPushButton* export_keys_button_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QPushButton* receive_button_ = nullptr;
    QPushButton* cancel_button_ = nullptr;
    QPushButton* copy_link_button_ = nullptr;
    QPushButton* copy_id_button_ = nullptr;
    QPushButton* open_downloads_button_ = nullptr;
    QProgressBar* progress_bar_ = nullptr;
    QLabel* transfer_id_label_ = nullptr;

    std::unique_ptr<KeyStore> keystore_;
    TransferEngine engine_;
    std::thread worker_thread_;
    std::atomic<bool> busy_{false};
    QString current_transfer_id_;
    QString current_share_link_;
    ServerAddress last_server_;  // relay used for the most recent upload

    void start_send();
    void start_receive();
    bool setup_keys(std::string& problem);
    bool unlock_keys(std::string& problem);
    std::string keychain_account() const;
    void remember_passphrase(const std::string& passphrase);
    void update_key_status();
    void set_passphrase_action();
    void change_passphrase_action();
    void remove_passphrase_action();
    void forget_saved_passphrase();

    void add_contact();
    void add_contact_from_card();
    void add_contact_from_files();
    std::optional<QString> ask_contact_name(const QString& suggested);
    // `bundle` is set when the contact came from a v2 card, whose encryption key is signed.
    void finish_add_contact(const QString& name,
                            const std::vector<uint8_t>& pub_kem,
                            const std::vector<uint8_t>& pub_dsa,
                            const std::string& card_server,
                            const IdentityBundle* bundle);
    void remove_contact();
    void copy_contact_card();
    void export_keys();
    void copy_share_link();
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
