#include "chat_widget.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "sharing.h"

#include <cstdio>

#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDialog>
#include <QFileDialog>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollBar>
#include <QSettings>
#include <QStandardPaths>
#include <QTimer>
#include <QVBoxLayout>

#include <map>
#include <vector>

namespace {

QString qstr(const std::string& s) { return QString::fromStdString(s); }

QString formatted(const std::string& fp) { return qstr(CryptoEngine::format_fingerprint(fp)); }

QString status_word(int status, bool outgoing) {
    if (!outgoing) return QString();
    switch (status) {
        case 0: return "  (waiting to send)";
        case 1: return "  (sent)";
        case 2: return "  (delivered)";
        default: return "  (read)";
    }
}

void plain_box(QMessageBox& box) { box.setTextFormat(Qt::PlainText); }

// "3.1 MB", for telling someone how big a file is before they choose to fetch it.
static QString human_size(uint64_t bytes) {
    char buf[40];
    if (bytes < 1024) std::snprintf(buf, sizeof(buf), "%llu bytes", static_cast<unsigned long long>(bytes));
    else if (bytes < 1024ull * 1024) std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    else if (bytes < 1024ull * 1024 * 1024) std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else std::snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return QString(buf);
}

// Where an attachment stands, in words.
static QString attachment_state_text(MessagingEngine& engine, const MessagingEngine::AttachmentView& a) {
    auto number = [](size_t n) { return QString::number(static_cast<qulonglong>(n)); };
    const QString expires = QDateTime::fromSecsSinceEpoch(a.expires_at).toString("d MMM");
    uint64_t done = 0, total = 0;
    const bool moving = engine.attachment_progress(a.file_id, done, total) && total > 0;
    const QString percent = moving ? QString::number(static_cast<qulonglong>(done * 100 / total)) + "%" : QString();
    switch (a.state) {
        case HistoryStore::AttachUploading: return moving ? "uploading " + percent : QString("waiting to upload");
        case HistoryStore::AttachDownloading: return moving ? "downloading " + percent : QString("downloading");
        case HistoryStore::AttachAvailable:
            if (a.outgoing) return number(a.redeemed) + " of " + number(a.recipients) + " have it, until " + expires;
            return "click to download, until " + expires + (a.note.empty() ? QString() : "  (last try: " + qstr(a.note) + ")");
        case HistoryStore::AttachTransferred: return a.outgoing ? QString("everyone has it") : "saved to " + qstr(a.saved_path);
        case HistoryStore::AttachExpired: return QString("expired: it is no longer on the relay");
        case HistoryStore::AttachWithdrawn: return a.outgoing ? QString("you withdrew it") : QString("the sender took it back");
        case HistoryStore::AttachFailed: return "could not be sent: " + qstr(a.note);
        default:
            if (!a.outgoing && a.note.rfind("Waiting", 0) == 0) return qstr(a.note) + "...";  // not an error: its key is on the way
            return a.outgoing ? QString("no longer on the relay") : QString("can't be downloaded: it reached you without the key it needs, or isn't on the sender's own relay") +
                                       (a.note.empty() ? QString() : "  (" + qstr(a.note) + ")");
    }
}

// The line a chat shows for an attachment: what it is, how big, where it stands, and its caption.
static QString attachment_line(MessagingEngine& engine, const MessagingEngine::AttachmentView& a, const std::string& caption, bool& moving) {
    QString text = "[file] " + qstr(a.name) + " (" + human_size(a.size) + ")  -  " + attachment_state_text(engine, a);
    if (!caption.empty()) text += "\n    " + qstr(caption);
    moving |= a.state == HistoryStore::AttachUploading || a.state == HistoryStore::AttachDownloading;
    return text;
}

// What a message to a group has achieved, in words that are true: how many of the members it has
// reached at each stage. (Each member has their own state; see show_group_delivery.)
QString group_status_word(const std::vector<MessagingEngine::MemberDelivery>& members) {
    const size_t total = members.size();
    size_t sent = 0, delivered = 0, read = 0;
    for (const auto& d : members) {
        if (d.status >= 1) sent++;
        if (d.status >= 2) delivered++;
        if (d.status >= 3) read++;
    }
    auto of = [total](size_t n) { return QString::number(static_cast<qulonglong>(n)) + " of " + QString::number(static_cast<qulonglong>(total)); };
    if (total == 0) return "  (waiting to send)";
    if (read == total) return "  (read by everyone)";
    if (delivered == total) return read ? "  (delivered to everyone, read by " + of(read) + ")" : QString("  (delivered to everyone)");
    if (sent == total) return delivered ? "  (sent to everyone, delivered to " + of(delivered) + ")" : QString("  (sent to everyone)");
    if (sent > 0) return "  (sent to " + of(sent) + ")";
    return "  (waiting to send)";
}

// One member's state in words, including why it may be stuck.
QString member_status_word(int status, bool reachable) {
    switch (status) {
        case 0: return reachable ? QString("waiting to send") : QString("waiting: you can't write to them yet (their key arrives when they join)");
        case 1: return "sent, not confirmed yet (it is waiting for them on the relay, or they have receipts off)";
        case 2: return "delivered";
        default: return "read";
    }
}

// Qt shows a tooltip as rich text if it looks like HTML, and group titles and members' names come
// from other people. So escape them and build the markup ourselves.
QString plain_tooltip(const QString& text) {
    return text.toHtmlEscaped().replace(QString("\n"), QString("<br>"));
}

QString group_title(const std::string& title) { return title.empty() ? QString("(no name)") : qstr(title); }

// The members of a group, each with where we know them from; and what's missing if it isn't ready.
QString group_tooltip(const MessagingEngine::GroupSummary& g) {
    QString text = "Members:";
    QString waiting;
    for (const auto& m : g.members) {
        text += "\n" + qstr(m.name) + " (" + qstr(m.label) + ")";
        if (!m.can_send) waiting += (waiting.isEmpty() ? "" : ", ") + qstr(m.name);
    }
    if (!g.ready) text += "\n\nSetting up: you can't write to " + waiting + " yet. Their keys arrive when they accept the invitation.";
    return plain_tooltip(text);
}

}  // namespace

ChatWidget::ChatWidget(KeyStore& keys, const std::filesystem::path& history_path, QWidget* parent)
    : QWidget(parent), keys_(keys) {
    auto* root = new QVBoxLayout(this);

    // --- Top bar ---
    auto* top = new QHBoxLayout();
    status_label_ = new QLabel("Messaging", this);
    status_label_->setTextFormat(Qt::PlainText);
    setup_button_ = new QPushButton("Set up messaging…", this);
    requests_button_ = new QPushButton("Message requests", this);
    cards_button_ = new QPushButton("Cards issued…", this);
    new_group_button_ = new QPushButton("New group…", this);
    invites_button_ = new QPushButton("Group invitations", this);
    deletions_button_ = new QPushButton("Deletion requests", this);
    deletions_button_->setToolTip("Other people asking to delete a chat, or messages in it, for everyone. It only happens if everyone agrees.");
    relay_invite_button_ = new QPushButton("Relay invites…", this);
    relay_invite_button_->setToolTip("Make a one-time invite so a friend can use this relay (you are vouching for them), and manage the ones you made.");
    top->addWidget(status_label_, 1);
    top->addWidget(setup_button_);
    top->addWidget(requests_button_);
    top->addWidget(invites_button_);
    top->addWidget(deletions_button_);
    top->addWidget(new_group_button_);
    top->addWidget(relay_invite_button_);
    restore_button_ = new QPushButton("Restore history…", this);
    restore_button_->setToolTip("After reinstalling: get your saved chats back from the relay");
    top->addWidget(restore_button_);
    top->addWidget(cards_button_);
    root->addLayout(top);

    // --- Contacts and conversation ---
    auto* body = new QHBoxLayout();
    auto* left = new QVBoxLayout();
    contacts_ = new QListWidget(this);
    contacts_->setMinimumWidth(170);
    contacts_->setMaximumWidth(230);
    left->addWidget(contacts_, 3);
    groups_label_ = new QLabel("Groups", this);
    groups_label_->setTextFormat(Qt::PlainText);
    groups_ = new QListWidget(this);
    groups_->setMinimumWidth(170);
    groups_->setMaximumWidth(230);
    left->addWidget(groups_label_);
    left->addWidget(groups_, 2);
    groups_label_->setVisible(false);  // shown once there is a group
    groups_->setVisible(false);
    body->addLayout(left);

    auto* right = new QVBoxLayout();
    auto* header_row = new QHBoxLayout();
    header_label_ = new QLabel("Choose a contact or group", this);
    header_label_->setTextFormat(Qt::PlainText);
    header_label_->setWordWrap(true);
    delivery_box_ = new QCheckBox("Delivery receipts", this);
    read_box_ = new QCheckBox("Read receipts", this);
    delivery_box_->setToolTip("Tell them when a message reaches this device");
    read_box_->setToolTip("Tell them when you have read their messages");
    revoke_button_ = new QPushButton("Revoke access…", this);
    revoke_button_->setToolTip("Stop this person from sending you anything with the cards and tokens you gave them");
    delete_chat_button_ = new QPushButton("Delete chat…", this);
    delete_chat_button_->setToolTip("Ask everyone in this chat to delete it, from the relay and from every device. It only happens if everyone agrees.");
    people_button_ = new QPushButton("Verify…", this);
    people_button_->setToolTip("See a fingerprint to compare with the person, and mark them as verified");
    header_row->addWidget(header_label_, 1);
    header_row->addWidget(delivery_box_);
    header_row->addWidget(read_box_);
    header_row->addWidget(people_button_);
    header_row->addWidget(delete_chat_button_);
    header_row->addWidget(revoke_button_);
    right->addLayout(header_row);

    messages_ = new QListWidget(this);
    messages_->setWordWrap(true);
    messages_->setSelectionMode(QAbstractItemView::NoSelection);
    messages_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    right->addWidget(messages_, 1);

    auto* input_row = new QHBoxLayout();
    input_ = new QLineEdit(this);
    input_->setPlaceholderText("Write a message…");
    send_button_ = new QPushButton("Send", this);
    attach_button_ = new QPushButton("Attach…", this);
    attach_button_->setToolTip("Send a file. What you have typed is sent with it as a caption.");
    input_row->addWidget(input_, 1);
    input_row->addWidget(attach_button_);
    input_row->addWidget(send_button_);
    right->addLayout(input_row);
    body->addLayout(right, 1);
    root->addLayout(body, 1);

    notice_label_ = new QLabel(this);
    notice_label_->setTextFormat(Qt::PlainText);
    notice_label_->setWordWrap(true);
    root->addWidget(notice_label_);

    // --- The engine ---
    try {
        engine_ = std::make_unique<MessagingEngine>(keys_, history_path);
        QString name = QSettings().value("display_name").toString();
        if (name.isEmpty()) name = qEnvironmentVariable("USER", qEnvironmentVariable("USERNAME"));
        engine_->set_display_name(name.toStdString());
    } catch (const std::exception& e) {
        status_label_->setText("Messaging is unavailable: " + qstr(e.what()));
        setup_button_->setEnabled(false);
        requests_button_->setEnabled(false);
        cards_button_->setEnabled(false);
        new_group_button_->setEnabled(false);
        relay_invite_button_->setEnabled(false);
        restore_button_->setEnabled(false);
        deletions_button_->setEnabled(false);
        delete_chat_button_->setEnabled(false);
        invites_button_->setEnabled(false);
        input_->setEnabled(false);
        send_button_->setEnabled(false);
        attach_button_->setEnabled(false);
        delivery_box_->setEnabled(false);
        read_box_->setEnabled(false);
        revoke_button_->setEnabled(false);
        people_button_->setEnabled(false);
        return;
    }

    connect(setup_button_, &QPushButton::clicked, this, [this] { setup_messaging(); });
    connect(requests_button_, &QPushButton::clicked, this, [this] { review_requests(); });
    connect(cards_button_, &QPushButton::clicked, this, [this] { show_cards_issued(); });
    connect(new_group_button_, &QPushButton::clicked, this, [this] { create_group_dialog(); });
    connect(relay_invite_button_, &QPushButton::clicked, this, [this] { make_relay_invite(); });
    connect(restore_button_, &QPushButton::clicked, this, [this] { restore_history(); });
    connect(deletions_button_, &QPushButton::clicked, this, [this] { review_deletions(); });
    connect(delete_chat_button_, &QPushButton::clicked, this, [this] { request_delete_chat(); });
    connect(invites_button_, &QPushButton::clicked, this, [this] { review_group_invites(); });
    connect(revoke_button_, &QPushButton::clicked, this, [this] { revoke_access_for_current(); });
    connect(people_button_, &QPushButton::clicked, this, [this] { people_clicked(); });
    connect(send_button_, &QPushButton::clicked, this, [this] { send_current(); });
    connect(attach_button_, &QPushButton::clicked, this, [this] { attach_file(); });
    auto* progress_timer = new QTimer(this);  // while a file is moving, redraw now and then so its progress shows
    connect(progress_timer, &QTimer::timeout, this, [this] {
        if (!animating_) return;
        const int keep = messages_->verticalScrollBar()->value();
        render_messages(false);
        messages_->verticalScrollBar()->setValue(keep);
    });
    progress_timer->start(700);
    auto* unread_timer = new QTimer(this);  // messages arrive while another tab is showing: keep the tab's count up to date
    connect(unread_timer, &QTimer::timeout, this, [this] { report_unread(); });
    unread_timer->start(1000);
    connect(input_, &QLineEdit::returnPressed, this, [this] { send_current(); });
    connect(contacts_, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item, QListWidgetItem*) {
        if (!updating_ui_ && item) select_contact(item->data(Qt::UserRole).toString());
    });
    connect(groups_, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item, QListWidgetItem*) {
        if (!updating_ui_ && item) select_group(item->data(Qt::UserRole).toString());
    });
    connect(messages_, &QListWidget::itemClicked, this, [this](QListWidgetItem* item) {
        if (!item) return;
        const QString attachment = item->data(Qt::UserRole + 1).toString();
        if (!attachment.isEmpty()) {  // an attachment: what can be done with it
            show_attachment(attachment);
            return;
        }
        if (!current_group_.isEmpty()) show_group_delivery(item->data(Qt::UserRole).toString());
    });
    connect(delivery_box_, &QCheckBox::toggled, this, [this](bool) { apply_receipt_settings(); });
    connect(read_box_, &QCheckBox::toggled, this, [this](bool) { apply_receipt_settings(); });

    // The pump runs off the UI thread; everything it does is reported through revision() and notices.
    worker_ = std::thread([this] {
        while (!stop_) {
            try {
                engine_->pump(250);
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));  // never let an error end the thread
            }
        }
    });

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, [this] { refresh_if_changed(); });
    timer_->start(400);
    refresh();
}

ChatWidget::~ChatWidget() {
    stop_ = true;
    if (worker_.joinable()) worker_.join();
}

// --- Refreshing ---

void ChatWidget::refresh() {
    if (!engine_) return;
    render_chats();
    render_groups();
    render_messages(true);
    update_header();
    report_unread();
}

// How many messages are waiting, across every chat and group, for the indicator on the Chats tab.
void ChatWidget::report_unread() {
    if (!engine_ || !on_unread_changed_) return;
    size_t total = 0;
    for (const auto& c : engine_->chats()) total += c.unread;
    for (const auto& g : engine_->groups()) total += g.unread;
    if (total == last_unread_) return;
    last_unread_ = total;
    on_unread_changed_(total);
}

void ChatWidget::refresh_if_changed() {
    if (!engine_) return;

    status_label_->setText(engine_->is_set_up() ? qstr(engine_->status()) : "Messaging isn't set up yet");
    setup_button_->setVisible(!engine_->is_set_up());
    cards_button_->setEnabled(engine_->is_set_up());
    new_group_button_->setEnabled(engine_->is_set_up());
    relay_invite_button_->setEnabled(engine_->is_set_up());
    restore_button_->setEnabled(engine_->is_set_up());
    const size_t pending = engine_->requests().size();
    requests_button_->setText(pending ? QString("Message requests (%1)").arg(static_cast<qulonglong>(pending)) : QString("Message requests"));
    const size_t invitations = engine_->group_invites().size();
    invites_button_->setText(invitations ? QString("Group invitations (%1)").arg(static_cast<qulonglong>(invitations)) : QString("Group invitations"));
    size_t deletion_asks = 0;
    for (const auto& d : engine_->deletions())
        if (d.state == HistoryStore::DeletionPending && !d.mine) deletion_asks++;
    deletions_button_->setText(deletion_asks ? QString("Deletion requests (%1)").arg(static_cast<qulonglong>(deletion_asks)) : QString("Deletion requests"));
    deletions_button_->setEnabled(engine_->is_set_up());

    for (const auto& line : engine_->take_notices()) {
        notice_label_->setText(qstr(line));
        if (line.find("passed on") != std::string::npos) {
            QMessageBox warn(QMessageBox::Warning, "A contact card may have been passed on", qstr(line), QMessageBox::Ok, this);
            plain_box(warn);
            warn.exec();
        }
    }

    const uint64_t revision = engine_->revision();
    if (revision != last_revision_) {
        last_revision_ = revision;
        // Looking at a conversation means reading it. Only checked when something changed, so a quiet
        // chat costs nothing; marking read bumps the revision once, and the next tick finds nothing to do.
        if (isVisible() && window()->isActiveWindow()) {
            if (!current_fp_.isEmpty()) engine_->mark_read(current_fp_.toStdString());
            else if (!current_group_.isEmpty()) engine_->mark_group_read(current_group_.toStdString());
        }
        render_chats();
        render_groups();
        render_messages(false);
        update_header();  // a group's "setting up" note changes as members' keys arrive
    }
}

void ChatWidget::render_chats() {
    updating_ui_ = true;
    contacts_->clear();
    int select_row = -1;
    int row = 0;
    for (const auto& c : engine_->chats()) {
        QString label = qstr(c.contact_name);
        if (c.unread) label += QString(" (%1)").arg(static_cast<qulonglong>(c.unread));
        auto* item = new QListWidgetItem(label);
        item->setData(Qt::UserRole, qstr(c.contact_fp));
        if (!c.can_send) {
            item->setForeground(Qt::gray);
            item->setToolTip(qstr(c.cannot_send_reason));
        }
        contacts_->addItem(item);
        if (qstr(c.contact_fp) == current_fp_) select_row = row;
        row++;
    }
    if (select_row >= 0) contacts_->setCurrentRow(select_row);
    updating_ui_ = false;
}

void ChatWidget::render_groups() {
    updating_ui_ = true;
    groups_->clear();
    int select_row = -1;
    int row = 0;
    for (const auto& g : engine_->groups()) {
        QString label = group_title(g.title);
        if (g.unread) label += QString(" (%1)").arg(static_cast<qulonglong>(g.unread));
        if (!g.ready) label += "  (setting up)";
        auto* item = new QListWidgetItem(label);
        item->setData(Qt::UserRole, qstr(g.id));
        item->setToolTip(group_tooltip(g));
        groups_->addItem(item);
        if (qstr(g.id) == current_group_) select_row = row;
        row++;
    }
    groups_label_->setVisible(row > 0);
    groups_->setVisible(row > 0);
    if (select_row >= 0) groups_->setCurrentRow(select_row);
    updating_ui_ = false;
}

void ChatWidget::render_messages(bool force_scroll) {
    if (!current_group_.isEmpty()) {
        render_group_messages(force_scroll);
        return;
    }
    if (current_fp_.isEmpty()) {
        messages_->clear();
        shown_messages_ = 0;
        return;
    }
    auto messages = engine_->messages(current_fp_.toStdString());
    messages_->clear();
    animating_ = false;
    for (const auto& m : messages) {
        QString when = QDateTime::fromSecsSinceEpoch(m.sent_at).toString("d MMM HH:mm");
        QString who = m.outgoing ? QString("You") : header_label_->property("contact_name").toString();
        if (m.deleted) {  // removed by agreement of everyone in the chat: only its place is left
            auto* gone = new QListWidgetItem("[" + when + "] (deleted by agreement)");
            gone->setTextAlignment(m.outgoing ? Qt::AlignRight : Qt::AlignLeft);
            messages_->addItem(gone);
            continue;
        }
        QString body = m.is_attachment ? attachment_line(*engine_, m.attachment, m.text, animating_) : qstr(m.text);
        QString text = "[" + when + "] " + who + ": " + body + (m.is_attachment ? QString() : status_word(m.status, m.outgoing));
        if (m.gap) text += "\n    (a message before this one is missing)";
        auto* item = new QListWidgetItem(text);
        item->setTextAlignment(m.outgoing ? Qt::AlignRight : Qt::AlignLeft);
        if (m.is_attachment) {
            item->setData(Qt::UserRole + 1, qstr(m.attachment.file_id));  // so a click can offer what can be done with it
            item->setToolTip("Click for what you can do with this file");
        }
        messages_->addItem(item);
    }
    if (force_scroll || messages.size() != shown_messages_) messages_->scrollToBottom();
    shown_messages_ = messages.size();
}

void ChatWidget::render_group_messages(bool force_scroll) {
    const std::string group = current_group_.toStdString();
    auto messages = engine_->group_messages(group);
    messages_->clear();
    animating_ = false;
    // Who has received what is looked up for the newest messages of ours that not everyone has read yet.
    size_t budget = 50;
    std::vector<bool> detailed(messages.size(), false);
    for (size_t i = messages.size(); i-- > 0 && budget > 0;)
        if (messages[i].outgoing && messages[i].status < 3) { detailed[i] = true; budget--; }
    for (size_t i = 0; i < messages.size(); i++) {
        const auto& m = messages[i];
        QString when = QDateTime::fromSecsSinceEpoch(m.sent_at).toString("d MMM HH:mm");
        QString who = m.outgoing ? QString("You") : qstr(m.sender_name);
        if (m.deleted) {  // removed by agreement of everyone in the chat: only its place is left
            auto* gone = new QListWidgetItem("[" + when + "] (deleted by agreement)");
            gone->setTextAlignment(m.outgoing ? Qt::AlignRight : Qt::AlignLeft);
            messages_->addItem(gone);
            continue;
        }
        QString status = status_word(m.status, m.outgoing);
        if (detailed[i]) status = group_status_word(engine_->group_delivery(group, m.message_id));
        QString body = m.is_attachment ? attachment_line(*engine_, m.attachment, m.text, animating_) : qstr(m.text);
        QString text = "[" + when + "] " + who + ": " + body + (m.is_attachment ? QString() : status);
        if (m.gap) text += "\n    (a message before this one is missing)";
        auto* item = new QListWidgetItem(text);
        item->setTextAlignment(m.outgoing ? Qt::AlignRight : Qt::AlignLeft);
        if (m.is_attachment) {
            item->setData(Qt::UserRole + 1, qstr(m.attachment.file_id));
            item->setToolTip("Click for what you can do with this file");
        } else if (m.outgoing) {
            item->setData(Qt::UserRole, qstr(m.message_id));  // so a click can show who has it
            item->setToolTip("Click to see who has received this message");
        }
        messages_->addItem(item);
    }
    if (force_scroll || messages.size() != shown_messages_) messages_->scrollToBottom();
    shown_messages_ = messages.size();
}

void ChatWidget::update_header() {
    if (!current_group_.isEmpty()) {
        // A group: its name, who is in it, and what we are still waiting for.
        const std::string id = current_group_.toStdString();
        QString title = "(this group)";
        QString members;
        QString waiting;
        for (const auto& g : engine_->groups()) {
            if (qstr(g.id) != current_group_) continue;
            title = group_title(g.title);
            for (const auto& m : g.members) {
                members += (members.isEmpty() ? "" : ", ") + qstr(m.name) + " (" + qstr(m.label) + ")";
                if (!m.can_send) waiting += (waiting.isEmpty() ? "" : ", ") + qstr(m.name);
            }
        }
        QString text = title + "\nWith " + members;
        if (!waiting.isEmpty()) text += "\nSetting up: can't write to " + waiting + " yet";
        header_label_->setProperty("contact_name", QString());
        header_label_->setText(text);
        delivery_box_->setEnabled(true);
        read_box_->setEnabled(true);
        revoke_button_->setEnabled(false);
        people_button_->setText("Members…");
        people_button_->setEnabled(true);
        delete_chat_button_->setEnabled(true);
        input_->setEnabled(true);
        input_->setPlaceholderText("Write a message to the group…");
        send_button_->setEnabled(true);
        attach_button_->setEnabled(true);
        bool delivery = true, read = true;
        engine_->group_receipts_enabled(id, &delivery, &read);
        updating_ui_ = true;
        delivery_box_->setChecked(delivery);
        read_box_->setChecked(read);
        updating_ui_ = false;
        return;
    }
    input_->setPlaceholderText("Write a message…");
    const bool have = !current_fp_.isEmpty();
    delivery_box_->setEnabled(have);
    read_box_->setEnabled(have);
    revoke_button_->setEnabled(have);
    people_button_->setText("Verify…");
    people_button_->setEnabled(have);
    delete_chat_button_->setEnabled(have);
    input_->setEnabled(have);
    send_button_->setEnabled(have);
    attach_button_->setEnabled(have);
    if (!have) {
        header_label_->setText("Choose a contact or group");
        return;
    }
    QString name;
    QString note;
    QString trust = "  (not verified)";
    for (const auto& c : engine_->chats()) {
        if (qstr(c.contact_fp) == current_fp_) {
            name = qstr(c.contact_name);
            if (c.verified) trust = "  (verified by you)";
            if (!c.can_send) note = "\n" + qstr(c.cannot_send_reason);
        }
    }
    header_label_->setProperty("contact_name", name);
    header_label_->setText(name + trust + note);

    bool delivery = true, read = true;
    engine_->receipts_enabled(current_fp_.toStdString(), &delivery, &read);
    updating_ui_ = true;
    delivery_box_->setChecked(delivery);
    read_box_->setChecked(read);
    updating_ui_ = false;
}

void ChatWidget::mark_verified(const std::string& fingerprint) {
    if (!engine_) return;
    engine_->set_verified(fingerprint, true);
    refresh();
}

// A person's fingerprint, to compare with them, and the choice to mark them verified (or take it back).
void ChatWidget::verify_person(const std::string& fingerprint, const QString& name) {
    const bool verified = engine_->is_verified(fingerprint);
    QString text = name + "'s fingerprint is:\n\n" + formatted(fingerprint) + "\n\n";
    if (verified) text += "You have marked this person as verified.";
    else text += "Compare it with " + name + " over a channel you trust (in person, or a call where you recognise them). "
                 "If it matches exactly, mark them as verified. If you can't check it, leave it as it is: people you haven't verified are shown that way.";
    QMessageBox box(QMessageBox::Question, "Fingerprint", text, QMessageBox::NoButton, this);
    plain_box(box);
    QAbstractButton* toggle = verified ? box.addButton("Remove verified mark", QMessageBox::DestructiveRole)
                                       : box.addButton("It matches: mark as verified", QMessageBox::AcceptRole);
    box.addButton("Close", QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() == toggle) {
        engine_->set_verified(fingerprint, !verified);
        refresh();
    }
}

void ChatWidget::people_clicked() {
    if (!current_group_.isEmpty()) {
        show_group_members();
        return;
    }
    if (current_fp_.isEmpty()) return;
    QString name;
    for (const auto& c : engine_->chats())
        if (qstr(c.contact_fp) == current_fp_) name = qstr(c.contact_name);
    verify_person(current_fp_.toStdString(), name);
}

// Everyone in the group, with where we know them from, and a way to check a fingerprint.
void ChatWidget::show_group_members() {
    QString creator_fp;
    std::vector<MessagingEngine::GroupMember> members;
    for (const auto& g : engine_->groups())
        if (qstr(g.id) == current_group_) {
            members = g.members;
            creator_fp = qstr(g.creator_fp);
        }
    QDialog dialog(this);
    dialog.setWindowTitle("Members");
    dialog.setMinimumWidth(520);
    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel("\"Introduced\" means you don't know that person yourself: whoever made the group vouched for them, and "
                             "nobody has checked their fingerprint with you. Select someone and choose Fingerprint to check it.", &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* list = new QListWidget(&dialog);
    for (const auto& m : members) {
        QString line = qstr(m.name) + "   |   " + qstr(m.label);
        if (qstr(m.fp) == creator_fp) line += "   |   made the group";
        if (!m.can_send) line += "   |   can't write to them yet";
        auto* item = new QListWidgetItem(line);
        item->setData(Qt::UserRole, qstr(m.fp));
        list->addItem(item);
    }
    layout->addWidget(list);

    auto* buttons = new QHBoxLayout();
    auto* fingerprint = new QPushButton("Fingerprint…", &dialog);
    auto* close = new QPushButton("Close", &dialog);
    buttons->addStretch();
    buttons->addWidget(fingerprint);
    buttons->addWidget(close);
    layout->addLayout(buttons);

    connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(fingerprint, &QPushButton::clicked, &dialog, [&] {
        auto* item = list->currentItem();
        if (!item) return;
        const QString fp = item->data(Qt::UserRole).toString();
        QString name;
        for (const auto& m : members)
            if (qstr(m.fp) == fp) name = qstr(m.name);
        verify_person(fp.toStdString(), name);
        // Show the new label right away.
        for (const auto& g : engine_->groups())
            if (qstr(g.id) == current_group_) members = g.members;
        QString label;
        for (const auto& m : members)
            if (qstr(m.fp) == fp) label = qstr(m.name) + "   |   " + qstr(m.label) + (m.can_send ? "" : "   |   can't write to them yet");
        if (!label.isEmpty()) item->setText(label);
    });
    dialog.exec();
}

// Click on one of your messages in a group: each member's own state, and why one may be stuck.
void ChatWidget::show_group_delivery(const QString& message_id) {
    if (current_group_.isEmpty() || message_id.isEmpty()) return;
    const std::string group = current_group_.toStdString();
    std::map<std::string, bool> reachable;
    for (const auto& g : engine_->groups())
        if (qstr(g.id) == current_group_)
            for (const auto& m : g.members) reachable[m.fp] = m.can_send;
    QString text = "Who has this message:\n";
    for (const auto& d : engine_->group_delivery(group, message_id.toStdString()))
        text += "\n    " + qstr(d.name) + ":  " + member_status_word(d.status, reachable[d.fp]);
    text += "\n\n\"Sent\" means the relay is holding it for them. \"Delivered\" appears when their app confirms it has stored it; "
            "someone who has turned delivery receipts off stays at \"sent\".";
    QMessageBox box(QMessageBox::Information, "Delivery", text, QMessageBox::Ok, this);
    plain_box(box);
    box.exec();
}

void ChatWidget::select_contact(const QString& fingerprint) {
    current_fp_ = fingerprint;
    current_group_.clear();
    updating_ui_ = true;
    groups_->setCurrentRow(-1);  // only one conversation is selected at a time
    updating_ui_ = false;
    if (isVisible() && window()->isActiveWindow()) engine_->mark_read(current_fp_.toStdString());
    update_header();
    render_messages(true);
    input_->setFocus();
}

void ChatWidget::select_group(const QString& group_id) {
    current_group_ = group_id;
    current_fp_.clear();
    updating_ui_ = true;
    contacts_->setCurrentRow(-1);
    updating_ui_ = false;
    if (isVisible() && window()->isActiveWindow()) engine_->mark_group_read(current_group_.toStdString());
    update_header();
    render_messages(true);
}

void ChatWidget::apply_receipt_settings() {
    if (updating_ui_) return;
    if (!current_group_.isEmpty()) {
        engine_->set_group_receipts(current_group_.toStdString(), delivery_box_->isChecked(), read_box_->isChecked());
        return;
    }
    if (current_fp_.isEmpty()) return;
    engine_->set_receipts(current_fp_.toStdString(), delivery_box_->isChecked(), read_box_->isChecked());
}

// --- Actions ---

void ChatWidget::send_current() {
    if (current_fp_.isEmpty() && current_group_.isEmpty()) return;
    const QString text = input_->text();
    if (text.trimmed().isEmpty()) return;
    std::string error;
    // A message to a group is queued for each member separately, whether or not all of them can be reached yet.
    const bool sent = !current_group_.isEmpty() ? engine_->send_group_text(current_group_.toStdString(), text.toStdString(), error)
                                                : engine_->send_text(current_fp_.toStdString(), text.toStdString(), error);
    if (!sent) {
        QMessageBox::warning(this, "Can't send", qstr(error));
        return;
    }
    input_->clear();
    last_revision_ = 0;  // show it right away
    refresh_if_changed();
}

void ChatWidget::setup_messaging() {
    bool ok = false;
    QString text = QInputDialog::getText(this, "Set up messaging",
                                         "Paste the relay invite you were given.\n"
                                         "It looks like pqft-relay://host/…/…",
                                         QLineEdit::Normal, "", &ok).trimmed();
    if (!ok || text.isEmpty()) return;

    auto invite = parse_relay_invite(text.toStdString());
    if (!invite) {
        QMessageBox::warning(this, "Set up messaging", "That invite isn't valid. Paste it exactly as the relay printed it.");
        return;
    }
    QMessageBox confirm(QMessageBox::Question, "Set up messaging",
                        "Create your mailbox on this relay?\n\n" + qstr(format_server_address(invite->server)) +
                        "\n\nThe relay's identity is pinned from this invite, so later connections will only be accepted "
                        "if they prove they hold this key:\n\n" + formatted(bytes_to_hex(invite->relay_id)),
                        QMessageBox::Yes | QMessageBox::No, this);
    plain_box(confirm);
    confirm.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);  // so the relay ID can be highlighted and copied
    QAbstractButton* copy_id = confirm.addButton("Copy relay ID", QMessageBox::ActionRole);
    while (true) {
        confirm.exec();
        if (confirm.clickedButton() != copy_id) break;
        QGuiApplication::clipboard()->setText(qstr(bytes_to_hex(invite->relay_id)));  // then the question is asked again
    }
    if (confirm.standardButton(confirm.clickedButton()) != QMessageBox::Yes) return;

    QGuiApplication::setOverrideCursor(Qt::WaitCursor);
    std::string error;
    const bool ok_setup = engine_->setup(*invite, error);
    QGuiApplication::restoreOverrideCursor();
    if (!ok_setup) {
        QMessageBox::warning(this, "Set up messaging", qstr(error));
        return;
    }
    // Sending files by transfer ID uses the same relay: set the Files tab to it, so it only has to be chosen once.
    const QString relay = qstr(format_server_address(invite->server));
    if (on_relay_chosen_) on_relay_chosen_(relay);
    QMessageBox::information(this, "Set up messaging",
                             "Messaging is ready. The relay for sending files on the Files tab has been set to the same one (" + relay + ").\n\n"
                             "Use \"Copy My Contact Card\" on the Files tab to give someone a card, and add the card they give you with +.");
    refresh();
}

void ChatWidget::copy_card_to_clipboard() {
    if (!engine_ || !engine_->is_set_up()) return;
    bool ok = false;
    QString label = QInputDialog::getText(this, "Contact card",
                                          "Who is this card for? (Only you see this. Each card gets its own\n"
                                          "permission, so you can revoke one without affecting anyone else.)",
                                          QLineEdit::Normal, "", &ok).trimmed();
    if (!ok) return;

    QGuiApplication::setOverrideCursor(Qt::WaitCursor);
    std::string card, error;
    const bool made = engine_->make_card(label.toStdString(), card, error);
    QGuiApplication::restoreOverrideCursor();
    if (!made) {
        QMessageBox::warning(this, "Contact card", qstr(error));
        return;
    }
    QGuiApplication::clipboard()->setText(qstr(card));

    QMessageBox info(QMessageBox::Information, "Contact card",
                     "Your contact card is on the clipboard. Paste it into a message to " +
                     (label.isEmpty() ? QString("your contact") : label) +
                     ".\n\nIt is signed with your identity key, so it can't be altered on the way without being noticed, and "
                     "it carries a permission to message you that is only for this card. A signature can't say who made a "
                     "card, so ask them to check this fingerprint with you in person or on a call:\n\n" +
                     formatted(keys_.own_fingerprint()),
                     QMessageBox::Ok, this);
    plain_box(info);
    info.exec();
}

void ChatWidget::review_requests() {
    for (const auto& r : engine_->requests()) {
        const QString who = r.display_name.empty() ? QString("someone") : qstr(r.display_name);
        QMessageBox box(QMessageBox::Question, "Message request",
                        who + " wants to message you. They say they are \"" + who + "\", but anyone can say that.\n\n"
                        "Their fingerprint:\n\n" + formatted(r.sender_fp) + "\n\nThey wrote (" +
                        QString::number(static_cast<qulonglong>(r.message_count)) + (r.message_count == 1 ? " message" : " messages") + "):\n\n" +
                        qstr(r.first_text.substr(0, 400)),
                        QMessageBox::NoButton, this);
        plain_box(box);
        QAbstractButton* accept = box.addButton("Accept…", QMessageBox::AcceptRole);
        QAbstractButton* decline = box.addButton("Decline", QMessageBox::DestructiveRole);
        box.addButton("Decide later", QMessageBox::RejectRole);
        box.exec();

        if (box.clickedButton() == decline) {
            engine_->decline_request(r.sender_fp);
        } else if (box.clickedButton() == accept) {
            bool ok = false;
            QString name = QInputDialog::getText(this, "Add contact", "Contact name (letters, digits, spaces, - _ .):",
                                                 QLineEdit::Normal, qstr(sanitize_contact_name(r.display_name)), &ok).trimmed();
            if (!ok || name.isEmpty()) continue;

            QMessageBox verify(QMessageBox::Question, "Verify fingerprint",
                               "Before accepting, confirm with " + name + " over a channel you trust (in person, or a call "
                               "where you recognise them) that their fingerprint is:\n\n" + formatted(r.sender_fp) +
                               "\n\nIf it doesn't match, this isn't who they claim to be.\n\nDoes the fingerprint match?",
                               QMessageBox::Yes | QMessageBox::No, this);
            plain_box(verify);
            verify.setDefaultButton(QMessageBox::No);
            if (verify.exec() != QMessageBox::Yes) continue;

            std::string error;
            if (!engine_->accept_request(r.sender_fp, name.toStdString(), error))
                QMessageBox::warning(this, "Message request", qstr(error));
        }
    }
    refresh();
}

// Only contacts you can message can be invited: the invitation is sent like a message.
void ChatWidget::create_group_dialog() {
    std::vector<MessagingEngine::ChatSummary> candidates;
    for (const auto& c : engine_->chats())
        if (c.can_send) candidates.push_back(c);
    if (candidates.empty()) {
        QMessageBox::information(this, "New group", "You can invite contacts you are able to message. Add a contact with their contact card first.");
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle("New group");
    dialog.setMinimumWidth(420);
    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel("Choose a name and the people to invite (up to 15). Each person is asked first and can decline. "
                             "The people in a group can't be changed afterwards.", &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);
    auto* title = new QLineEdit(&dialog);
    title->setPlaceholderText("Group name (optional)");
    layout->addWidget(title);
    auto* list = new QListWidget(&dialog);
    for (const auto& c : candidates) {
        auto* item = new QListWidgetItem(qstr(c.contact_name));
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Unchecked);
        item->setData(Qt::UserRole, qstr(c.contact_fp));
        list->addItem(item);
    }
    layout->addWidget(list);

    auto* buttons = new QHBoxLayout();
    auto* create = new QPushButton("Create and invite", &dialog);
    auto* cancel = new QPushButton("Cancel", &dialog);
    buttons->addStretch();
    buttons->addWidget(create);
    buttons->addWidget(cancel);
    layout->addLayout(buttons);

    QString created_id;
    connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);
    connect(create, &QPushButton::clicked, &dialog, [&] {
        std::vector<std::string> members;
        for (int i = 0; i < list->count(); i++) {
            auto* item = list->item(i);
            if (item->checkState() == Qt::Checked) members.push_back(item->data(Qt::UserRole).toString().toStdString());
        }
        if (members.empty()) {
            QMessageBox::information(&dialog, "New group", "Tick at least one person to invite.");
            return;
        }
        std::string id, error;
        if (!engine_->create_group(title->text().trimmed().toStdString(), members, id, error)) {
            QMessageBox::warning(&dialog, "New group", qstr(error));
            return;
        }
        created_id = qstr(id);
        dialog.accept();
    });
    dialog.exec();

    if (!created_id.isEmpty()) {
        select_group(created_id);
        refresh();
    }
}

// Shows a freshly made invite: the string to give a friend, and what handing it over means.
static void show_invite_box(QWidget* parent, const std::string& invite) {
    QString text = "Give this to one friend. They paste it into \"Set up messaging\". It works once and expires after 14 days.\n\n" +
                   qstr(invite) +
                   "\n\nYou are vouching for whoever uses it: the relay's operator can see that you invited them.\n\n"
                   "The invite names the relay by the address you use. If your friend reaches the relay a different way, "
                   "change the address part (after pqft-relay://) before sending it.";
    QMessageBox box(QMessageBox::Information, "New relay invite", text, QMessageBox::NoButton, parent);
    box.setTextFormat(Qt::PlainText);
    QAbstractButton* copy = box.addButton("Copy invite", QMessageBox::AcceptRole);
    box.addButton("Close", QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() == copy) QGuiApplication::clipboard()->setText(qstr(invite));
}

// Your invites on this relay: make a new one for a friend (which vouches for them), see which are
// still unused, and cancel one if it went to the wrong place.
void ChatWidget::make_relay_invite() {
    QDialog dialog(this);
    dialog.setWindowTitle("Relay invites");
    dialog.setMinimumWidth(500);
    auto* layout = new QVBoxLayout(&dialog);
    auto* summary = new QLabel(&dialog);
    summary->setWordWrap(true);
    summary->setTextFormat(Qt::PlainText);
    layout->addWidget(summary);
    auto* unused = new QListWidget(&dialog);
    layout->addWidget(unused);
    auto* joined = new QLabel(&dialog);
    joined->setWordWrap(true);
    joined->setTextFormat(Qt::PlainText);
    layout->addWidget(joined);

    auto* buttons = new QHBoxLayout();
    auto* make = new QPushButton("New invite", &dialog);
    auto* cancel = new QPushButton("Cancel selected invite", &dialog);
    auto* close = new QPushButton("Close", &dialog);
    buttons->addStretch();
    buttons->addWidget(make);
    buttons->addWidget(cancel);
    buttons->addWidget(close);
    layout->addLayout(buttons);

    auto reload = [&] {
        MessagingEngine::RelayInviteStatus status;
        std::string error;
        unused->clear();
        if (!engine_->relay_invite_status(status, error)) {
            summary->setText(qstr(error));
            joined->setText(QString());
            make->setEnabled(false);
            cancel->setEnabled(false);
            return;
        }
        auto number = [](size_t n) { return QString::number(static_cast<qulonglong>(n)); };
        summary->setText("This relay lets you have " + number(status.max_unused) + " unused invites at once and invite " + number(status.max_total) +
                         " people in all. You have " + number(status.unused.size()) + " unused, and " + number(status.joined.size()) +
                         " people have joined through you.\n\nThe relay doesn't know who each invite was for, only when it expires.");
        for (const auto& u : status.unused) {
            auto* item = new QListWidgetItem("Unused, expires " + QDateTime::fromSecsSinceEpoch(u.expires_at).toString("d MMM yyyy"));
            item->setData(Qt::UserRole, qstr(u.id));
            unused->addItem(item);
        }
        QString who;
        for (const auto& j : status.joined)
            who += (who.isEmpty() ? "" : ", ") + QDateTime::fromSecsSinceEpoch(j.joined_at).toString("d MMM yyyy") + " (mailbox " + qstr(j.mailbox) + ")";
        joined->setText(who.isEmpty() ? QString("Nobody has joined through you yet.") : "Joined through you: " + who);
        make->setEnabled(status.unused.size() < status.max_unused && status.unused.size() + status.joined.size() < status.max_total);
        cancel->setEnabled(!status.unused.empty());
    };

    connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(make, &QPushButton::clicked, &dialog, [&] {
        std::string invite, error;
        QGuiApplication::setOverrideCursor(Qt::WaitCursor);
        const bool ok = engine_->create_relay_invite(invite, error);
        QGuiApplication::restoreOverrideCursor();
        if (!ok) {
            QMessageBox::warning(&dialog, "Relay invite", qstr(error));
            return;
        }
        show_invite_box(&dialog, invite);
        reload();
    });
    connect(cancel, &QPushButton::clicked, &dialog, [&] {
        auto* item = unused->currentItem();
        if (!item) {
            QMessageBox::information(&dialog, "Relay invites", "Select an unused invite to cancel.");
            return;
        }
        if (QMessageBox::question(&dialog, "Cancel invite", "Cancel this invite? Whoever you gave it to will no longer be able to use it.") != QMessageBox::Yes) return;
        std::string error;
        if (!engine_->cancel_relay_invite(item->data(Qt::UserRole).toString().toStdString(), error)) QMessageBox::warning(&dialog, "Relay invites", qstr(error));
        reload();
    });
    reload();
    dialog.exec();
}

// After a reinstall: read the user's chats back from the relay. It needs the same keys folder and passphrase as
// before, because the saved keyring and every archive are encrypted under keys derived from them.
void ChatWidget::restore_history() {
    QMessageBox ask(QMessageBox::Question, "Restore history",
                    "This fetches your saved chats from the relay, using the keys on this computer, and rebuilds them here.\n\n"
                    "It only works for chats that had been archived, and only with the same keys folder and passphrase you used before: "
                    "without those, there is nothing to restore from. Private chats are never restored.\n\nRestore now?",
                    QMessageBox::Yes | QMessageBox::No, this);
    plain_box(ask);
    if (ask.exec() != QMessageBox::Yes) return;
    MessagingEngine::RestoreReport report;
    std::string error;
    QGuiApplication::setOverrideCursor(Qt::WaitCursor);
    const bool ok = engine_->restore_from_relay(report, error);
    QGuiApplication::restoreOverrideCursor();
    if (!ok) {
        QMessageBox::warning(this, "Restore history", qstr(error));
        return;
    }
    auto number = [](size_t n) { return QString::number(static_cast<qulonglong>(n)); };
    QString text = "Restored " + number(report.chats_restored) + " chats, with " + number(report.messages) + " messages.";
    if (report.chats_skipped) {
        text += "\n\n" + number(report.chats_skipped) + " could not be restored:";
        size_t shown = 0;
        for (const auto& note : report.notes) {
            if (shown++ == 6) { text += "\n...and more"; break; }
            text += "\n  " + qstr(note);
        }
    }
    text += "\n\nChats from before archives existed, and Private chats, cannot come back.";
    QMessageBox done(QMessageBox::Information, "Restore history", text, QMessageBox::Ok, this);
    plain_box(done);
    done.exec();
    refresh();
}

// What a chat is called, for telling someone which one a request is about.
static QString chat_label(MessagingEngine& engine, const std::string& conversation_id) {
    for (const auto& g : engine.groups())
        if (g.id == conversation_id) return group_title(g.title);
    for (const auto& c : engine.chats())
        if (engine.direct_conversation_id(c.contact_fp) == std::optional<std::string>(conversation_id)) return qstr(c.contact_name);
    return QString("a chat");
}

// Other people asking to delete a chat, or messages in it, for everyone. Deleting needs every member to agree:
// answering "don't delete", or not answering, means nothing is deleted.
void ChatWidget::review_deletions() {
    for (const auto& d : engine_->deletions()) {
        if (d.state != HistoryStore::DeletionPending || d.mine) continue;
        auto number = [](size_t n) { return QString::number(static_cast<qulonglong>(n)); };
        QString what = d.whole_chat ? QString("the whole chat") : number(d.entries) + (d.entries == 1 ? " message" : " messages");
        QString text = qstr(d.requester_name) + " wants to delete " + what + " in " + chat_label(*engine_, d.conversation_id) + ", for everyone.\n\n"
                       "It would be removed from the relay and from every member's device, and can't be brought back. It only happens if every member agrees: "
                       "if you say no, or don't answer, nothing is deleted.\n\n" +
                       number(d.accepted) + " of " + number(d.members) + " have agreed so far. The request lapses on " +
                       QDateTime::fromSecsSinceEpoch(d.expires_at).toString("d MMM yyyy") + ".";
        QMessageBox box(QMessageBox::Question, "Deletion request", text, QMessageBox::NoButton, this);
        plain_box(box);
        QAbstractButton* agree = box.addButton("Delete for everyone", QMessageBox::AcceptRole);
        QAbstractButton* refuse = box.addButton("Don't delete", QMessageBox::DestructiveRole);
        box.addButton("Decide later", QMessageBox::RejectRole);
        box.exec();
        if (box.clickedButton() == refuse) {
            engine_->decline_deletion(d.op_id);
        } else if (box.clickedButton() == agree) {
            std::string error;
            if (!engine_->accept_deletion(d.op_id, error)) QMessageBox::warning(this, "Deletion request", qstr(error));
        }
    }
    refresh();
}

// Ask everyone in the chat on screen to delete it.
void ChatWidget::request_delete_chat() {
    std::string id;
    if (!current_group_.isEmpty()) {
        id = current_group_.toStdString();
    } else if (!current_fp_.isEmpty()) {
        auto direct = engine_->direct_conversation_id(current_fp_.toStdString());
        if (!direct) return;
        id = *direct;
    } else {
        return;
    }
    QMessageBox ask(QMessageBox::Question, "Delete chat",
                    "Ask everyone in this chat to delete it?\n\n"
                    "If EVERY member agrees, the chat is removed from the relay and from everyone's device, and can't be brought back. "
                    "If anyone says no, or doesn't answer within 7 days, nothing is deleted.\n\n"
                    "Only what is in the chat's archive (made after archives were introduced) is removed from the relay.",
                    QMessageBox::Yes | QMessageBox::No, this);
    plain_box(ask);
    if (ask.exec() != QMessageBox::Yes) return;
    std::string error;
    if (!engine_->request_chat_deletion(id, error)) {
        QMessageBox::warning(this, "Delete chat", qstr(error));
        return;
    }
    QMessageBox done(QMessageBox::Information, "Delete chat", "Everyone in the chat has been asked. You will be told when it is done.", QMessageBox::Ok, this);
    plain_box(done);
    done.exec();
}

// Choose a file to send in the chat on screen. What is typed in the message box goes with it as a caption. The file is
// uploaded in the background; the message shows its progress and reaches the others only once the file is on the relay.
void ChatWidget::attach_file() {
    const bool group = !current_group_.isEmpty();
    if (!group && current_fp_.isEmpty()) return;
    const QString chosen = QFileDialog::getOpenFileName(this, "Choose a file to send", QString());
    if (chosen.isEmpty()) return;
    bool ok = false;
    const int days = QInputDialog::getInt(this, "Keep it on the relay", "For how many days should the relay keep it for the others to download? (1 to 30)", 7, 1, 30, 1, &ok);
    if (!ok) return;
    const std::string caption = input_->text().trimmed().toStdString();
    const auto path = std::filesystem::u8path(chosen.toStdString());
    std::string error;
    QGuiApplication::setOverrideCursor(Qt::WaitCursor);  // a very large file takes a moment to measure
    const bool sent = group ? engine_->send_group_attachment(current_group_.toStdString(), path, caption, days, error)
                            : engine_->send_attachment(current_fp_.toStdString(), path, caption, days, error);
    QGuiApplication::restoreOverrideCursor();
    if (!sent) {
        QMessageBox::warning(this, "Attach a file", qstr(error));
        return;
    }
    input_->clear();
    refresh();
}

// What can be done with an attachment, depending on where it stands. Nothing is ever fetched or opened without being asked.
void ChatWidget::show_attachment(const QString& file_id) {
    auto a = engine_->attachment(file_id.toStdString());
    if (!a) return;
    QString text = qstr(a->name) + "\n" + human_size(a->size) + "\n\n" + attachment_state_text(*engine_, *a);
    if (a->state == HistoryStore::AttachAvailable && !a->outgoing)
        text += "\n\nIt is kept on the sender's relay, encrypted. Downloading uses it up for you: it is saved to the folder you choose, under a name that can't replace anything, "
                "after it has been checked against what the sender signed. It is never opened for you.";
    QMessageBox box(QMessageBox::Information, "Attachment", text, QMessageBox::NoButton, this);
    plain_box(box);
    QAbstractButton* download = nullptr;
    QAbstractButton* copy = nullptr;
    QAbstractButton* withdraw = nullptr;
    if (!a->outgoing && a->state == HistoryStore::AttachAvailable) download = box.addButton("Download…", QMessageBox::AcceptRole);
    if (!a->outgoing && a->state == HistoryStore::AttachTransferred && !a->saved_path.empty()) copy = box.addButton("Copy the file's location", QMessageBox::AcceptRole);
    if (a->outgoing && (a->state == HistoryStore::AttachAvailable || a->state == HistoryStore::AttachUploading)) withdraw = box.addButton("Withdraw it", QMessageBox::DestructiveRole);
    box.addButton("Close", QMessageBox::RejectRole);
    box.exec();
    QAbstractButton* clicked = box.clickedButton();
    if (download && clicked == download) {
        const QString start = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        const QString folder = QFileDialog::getExistingDirectory(this, "Save " + qstr(a->name) + " (" + human_size(a->size) + ") to", start);
        if (folder.isEmpty()) return;
        std::string error;
        if (!engine_->download_attachment(file_id.toStdString(), std::filesystem::u8path(folder.toStdString()), error)) QMessageBox::warning(this, "Download", qstr(error));
        refresh();
    } else if (copy && clicked == copy) {
        QGuiApplication::clipboard()->setText(qstr(a->saved_path));
    } else if (withdraw && clicked == withdraw) {
        if (QMessageBox::question(this, "Withdraw", "Take this file back? The relay deletes it, and anyone who hasn't downloaded it yet won't be able to.") != QMessageBox::Yes) return;
        std::string error;
        if (!engine_->withdraw_attachment(file_id.toStdString(), error)) QMessageBox::warning(this, "Withdraw", qstr(error));
        refresh();
    }
}

void ChatWidget::review_group_invites() {
    for (const auto& invite : engine_->group_invites()) {
        QString members;
        bool any_introduced = false;
        for (const auto& m : invite.members) {
            members += "\n    " + qstr(m.name) + "  (" + qstr(m.label) + ")";
            any_introduced |= m.trust == MessagingEngine::Trust::Introduced;
        }
        QString text = qstr(invite.creator_name) + " invited you to the group " + group_title(invite.title) + ".\n\nThe others in it:" + members;
        if (any_introduced)
            text += "\n\n\"Introduced\" means you don't know that person yourself: whoever made the group vouched for them, and nobody "
                    "has checked their fingerprint with you. You can check it with them later.";
        if (invite.held_messages)
            text += "\n\n" + QString::number(static_cast<qulonglong>(invite.held_messages)) + (invite.held_messages == 1 ? " message has" : " messages have") +
                    " arrived for it while you were deciding. You will see them if you join.";
        QMessageBox box(QMessageBox::Question, "Group invitation", text, QMessageBox::NoButton, this);
        plain_box(box);
        QAbstractButton* join = box.addButton("Join", QMessageBox::AcceptRole);
        QAbstractButton* decline = box.addButton("Decline", QMessageBox::DestructiveRole);
        box.addButton("Decide later", QMessageBox::RejectRole);
        box.exec();

        if (box.clickedButton() == decline) {
            engine_->decline_group_invite(invite.id);
        } else if (box.clickedButton() == join) {
            std::string error;
            if (engine_->accept_group_invite(invite.id, error)) select_group(qstr(invite.id));
            else QMessageBox::warning(this, "Group invitation", qstr(error));
        }
    }
    refresh();
}

void ChatWidget::show_cards_issued() {
    auto tokens = engine_->issued_tokens();
    QDialog dialog(this);
    dialog.setWindowTitle("Cards issued");
    dialog.setMinimumWidth(520);
    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel("Every card you hand out carries its own permission to message you. Revoke one and only that "
                             "card stops working. \"Used by\" is the first person who wrote to you with it; if someone else "
                             "does later, the card was probably passed on.", &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* list = new QListWidget(&dialog);
    for (const auto& t : tokens) {
        QString line = qstr(t.label) + "   |   made " + QDateTime::fromSecsSinceEpoch(t.created_at).toString("d MMM yyyy");
        if (t.revoked) line += "   |   REVOKED";
        else if (t.used_by.empty()) line += "   |   not used yet";
        else line += "   |   used by " + qstr(t.used_by.substr(0, 16)) + "...";
        auto* item = new QListWidgetItem(line);
        item->setData(Qt::UserRole, static_cast<int>(&t - tokens.data()));
        if (t.revoked) item->setForeground(Qt::gray);
        list->addItem(item);
    }
    layout->addWidget(list);

    auto* buttons = new QHBoxLayout();
    auto* revoke = new QPushButton("Revoke selected card", &dialog);
    auto* close = new QPushButton("Close", &dialog);
    buttons->addStretch();
    buttons->addWidget(revoke);
    buttons->addWidget(close);
    layout->addLayout(buttons);

    connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(revoke, &QPushButton::clicked, &dialog, [&] {
        auto* item = list->currentItem();
        if (!item) return;
        const auto& token = tokens[static_cast<size_t>(item->data(Qt::UserRole).toInt())];
        if (token.revoked) return;
        std::string error;
        QGuiApplication::setOverrideCursor(Qt::WaitCursor);
        const bool done = engine_->revoke_token(token.hash, error);
        QGuiApplication::restoreOverrideCursor();
        if (!done) { QMessageBox::warning(&dialog, "Revoke", qstr(error)); return; }
        item->setText(item->text() + "   |   REVOKED");
        item->setForeground(Qt::gray);
    });
    dialog.exec();
}

void ChatWidget::revoke_access_for_current() {
    if (current_fp_.isEmpty()) return;
    QMessageBox ask(QMessageBox::Warning, "Revoke access",
                    "Revoke every card and permission this person has been given?\n\nThey will no longer be able to send "
                    "you messages until you give them a new card. Your history stays as it is.",
                    QMessageBox::Yes | QMessageBox::No, this);
    plain_box(ask);
    ask.setDefaultButton(QMessageBox::No);
    if (ask.exec() != QMessageBox::Yes) return;

    std::string error;
    QGuiApplication::setOverrideCursor(Qt::WaitCursor);
    const int revoked = engine_->revoke_tokens_for(current_fp_.toStdString(), error);
    QGuiApplication::restoreOverrideCursor();
    if (revoked < 0) QMessageBox::warning(this, "Revoke access", qstr(error));
    else QMessageBox::information(this, "Revoke access", revoked ? QString("Revoked %1 permission(s).").arg(revoked) : QString("There was nothing to revoke."));
}
