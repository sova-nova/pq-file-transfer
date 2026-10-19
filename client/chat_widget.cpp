#include "chat_widget.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "sharing.h"

#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDialog>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <QVBoxLayout>

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
    top->addWidget(status_label_, 1);
    top->addWidget(setup_button_);
    top->addWidget(requests_button_);
    top->addWidget(cards_button_);
    root->addLayout(top);

    // --- Contacts and conversation ---
    auto* body = new QHBoxLayout();
    contacts_ = new QListWidget(this);
    contacts_->setMinimumWidth(170);
    contacts_->setMaximumWidth(230);
    body->addWidget(contacts_);

    auto* right = new QVBoxLayout();
    auto* header_row = new QHBoxLayout();
    header_label_ = new QLabel("Choose a contact", this);
    header_label_->setTextFormat(Qt::PlainText);
    header_label_->setWordWrap(true);
    delivery_box_ = new QCheckBox("Delivery receipts", this);
    read_box_ = new QCheckBox("Read receipts", this);
    delivery_box_->setToolTip("Tell them when a message reaches this device");
    read_box_->setToolTip("Tell them when you have read their messages");
    revoke_button_ = new QPushButton("Revoke access…", this);
    revoke_button_->setToolTip("Stop this person from sending you anything with the cards and tokens you gave them");
    header_row->addWidget(header_label_, 1);
    header_row->addWidget(delivery_box_);
    header_row->addWidget(read_box_);
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
    input_row->addWidget(input_, 1);
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
        input_->setEnabled(false);
        send_button_->setEnabled(false);
        delivery_box_->setEnabled(false);
        read_box_->setEnabled(false);
        revoke_button_->setEnabled(false);
        return;
    }

    connect(setup_button_, &QPushButton::clicked, this, [this] { setup_messaging(); });
    connect(requests_button_, &QPushButton::clicked, this, [this] { review_requests(); });
    connect(cards_button_, &QPushButton::clicked, this, [this] { show_cards_issued(); });
    connect(revoke_button_, &QPushButton::clicked, this, [this] { revoke_access_for_current(); });
    connect(send_button_, &QPushButton::clicked, this, [this] { send_current(); });
    connect(input_, &QLineEdit::returnPressed, this, [this] { send_current(); });
    connect(contacts_, &QListWidget::currentItemChanged, this, [this](QListWidgetItem* item, QListWidgetItem*) {
        if (!updating_ui_ && item) select_contact(item->data(Qt::UserRole).toString());
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
    render_messages(true);
    update_header();
}

void ChatWidget::refresh_if_changed() {
    if (!engine_) return;

    status_label_->setText(engine_->is_set_up() ? qstr(engine_->status()) : "Messaging isn't set up yet");
    setup_button_->setVisible(!engine_->is_set_up());
    cards_button_->setEnabled(engine_->is_set_up());
    const size_t pending = engine_->requests().size();
    requests_button_->setText(pending ? QString("Message requests (%1)").arg(static_cast<qulonglong>(pending)) : QString("Message requests"));

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
        if (!current_fp_.isEmpty() && isVisible() && window()->isActiveWindow()) engine_->mark_read(current_fp_.toStdString());
        render_chats();
        render_messages(false);
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

void ChatWidget::render_messages(bool force_scroll) {
    if (current_fp_.isEmpty()) {
        messages_->clear();
        shown_messages_ = 0;
        return;
    }
    auto messages = engine_->messages(current_fp_.toStdString());
    messages_->clear();
    for (const auto& m : messages) {
        QString when = QDateTime::fromSecsSinceEpoch(m.sent_at).toString("d MMM HH:mm");
        QString who = m.outgoing ? QString("You") : header_label_->property("contact_name").toString();
        QString text = "[" + when + "] " + who + ": " + qstr(m.text) + status_word(m.status, m.outgoing);
        if (m.gap) text += "\n    (a message before this one is missing)";
        auto* item = new QListWidgetItem(text);
        item->setTextAlignment(m.outgoing ? Qt::AlignRight : Qt::AlignLeft);
        messages_->addItem(item);
    }
    if (force_scroll || messages.size() != shown_messages_) messages_->scrollToBottom();
    shown_messages_ = messages.size();
}

void ChatWidget::update_header() {
    const bool have = !current_fp_.isEmpty();
    delivery_box_->setEnabled(have);
    read_box_->setEnabled(have);
    revoke_button_->setEnabled(have);
    input_->setEnabled(have);
    send_button_->setEnabled(have);
    if (!have) {
        header_label_->setText("Choose a contact");
        return;
    }
    QString name;
    QString note;
    for (const auto& c : engine_->chats()) {
        if (qstr(c.contact_fp) == current_fp_) {
            name = qstr(c.contact_name);
            if (!c.can_send) note = "\n" + qstr(c.cannot_send_reason);
        }
    }
    header_label_->setProperty("contact_name", name);
    header_label_->setText(name + note);

    bool delivery = true, read = true;
    engine_->receipts_enabled(current_fp_.toStdString(), &delivery, &read);
    updating_ui_ = true;
    delivery_box_->setChecked(delivery);
    read_box_->setChecked(read);
    updating_ui_ = false;
}

void ChatWidget::select_contact(const QString& fingerprint) {
    current_fp_ = fingerprint;
    if (isVisible() && window()->isActiveWindow()) engine_->mark_read(current_fp_.toStdString());
    update_header();
    render_messages(true);
    input_->setFocus();
}

void ChatWidget::apply_receipt_settings() {
    if (updating_ui_ || current_fp_.isEmpty()) return;
    engine_->set_receipts(current_fp_.toStdString(), delivery_box_->isChecked(), read_box_->isChecked());
}

// --- Actions ---

void ChatWidget::send_current() {
    if (current_fp_.isEmpty()) return;
    const QString text = input_->text();
    if (text.trimmed().isEmpty()) return;
    std::string error;
    if (!engine_->send_text(current_fp_.toStdString(), text.toStdString(), error)) {
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
    if (confirm.exec() != QMessageBox::Yes) return;

    QGuiApplication::setOverrideCursor(Qt::WaitCursor);
    std::string error;
    const bool ok_setup = engine_->setup(*invite, error);
    QGuiApplication::restoreOverrideCursor();
    if (!ok_setup) {
        QMessageBox::warning(this, "Set up messaging", qstr(error));
        return;
    }
    QMessageBox::information(this, "Set up messaging",
                             "Messaging is ready. Use \"Copy My Contact Card\" on the Files tab to give someone a card, "
                             "and add the card they give you with +.");
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
