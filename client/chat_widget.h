#pragma once

#include <QWidget>

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

#include "messaging_engine.h"

class QCheckBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QTimer;

// The Chats tab: contact list, conversation view, message requests, relay setup and the list of
// contact cards the user has handed out. It owns the MessagingEngine and the worker thread that
// pumps it; the UI thread only ever reads state from the engine and queues messages into it.
class ChatWidget : public QWidget {
public:
    ChatWidget(KeyStore& keys, const std::filesystem::path& history_path, QWidget* parent = nullptr);
    ~ChatWidget() override;

    bool available() const { return engine_ != nullptr; }
    bool is_set_up() const { return engine_ && engine_->is_set_up(); }

    // Makes a contact card with a fresh send token for one person and puts it on the clipboard.
    void copy_card_to_clipboard();

    // Call after contacts were added or changed from outside this tab.
    void refresh();

private:
    void setup_messaging();
    void review_requests();
    void show_cards_issued();
    void revoke_access_for_current();
    void send_current();
    void select_contact(const QString& fingerprint);
    void apply_receipt_settings();
    void refresh_if_changed();
    void render_chats();
    void render_messages(bool force_scroll);
    void update_header();

    KeyStore& keys_;
    std::unique_ptr<MessagingEngine> engine_;
    std::thread worker_;
    std::atomic<bool> stop_{false};

    QLabel* status_label_ = nullptr;
    QLabel* notice_label_ = nullptr;
    QPushButton* setup_button_ = nullptr;
    QPushButton* requests_button_ = nullptr;
    QPushButton* cards_button_ = nullptr;
    QListWidget* contacts_ = nullptr;
    QLabel* header_label_ = nullptr;
    QCheckBox* delivery_box_ = nullptr;
    QCheckBox* read_box_ = nullptr;
    QPushButton* revoke_button_ = nullptr;
    QListWidget* messages_ = nullptr;
    QLineEdit* input_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QTimer* timer_ = nullptr;

    QString current_fp_;
    uint64_t last_revision_ = 0;
    size_t shown_messages_ = 0;
    bool updating_ui_ = false;
};
