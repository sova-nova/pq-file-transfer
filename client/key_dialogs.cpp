#include "key_dialogs.h"

#include "key_store.h"
#include "keychain.h"

#include <QCheckBox>
#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

QLabel* text_label(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);  // never interpret as HTML
    label->setWordWrap(true);
    return label;
}

QLineEdit* password_field(const QString& placeholder, QWidget* parent) {
    auto* edit = new QLineEdit(parent);
    edit->setEchoMode(QLineEdit::Password);
    edit->setPlaceholderText(placeholder);
    return edit;
}

QCheckBox* remember_checkbox(QWidget* parent) {
    auto* box = new QCheckBox("Remember on this computer (recommended)", parent);
    box->setToolTip("Keeps the passphrase in your system's keychain so you don't have to type it "
                    "each time you start the app.");
    box->setChecked(true);
    return box;
}

QLabel* error_label(QWidget* parent) {
    auto* label = text_label(QString(), parent);
    label->setStyleSheet("color: #c62828;");
    return label;
}

// The same passphrase must unlock on every operating system, so fix the Unicode form.
std::string to_passphrase(const QString& text) {
    return text.normalized(QString::NormalizationForm_C).toStdString();
}

}  // namespace

PassphraseChoice ask_new_passphrase(QWidget* parent, const QString& title, const QString& explanation,
                                    bool allow_skip) {
    QDialog dialog(parent);
    dialog.setWindowTitle(title);
    dialog.setMinimumWidth(480);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(text_label(explanation, &dialog));

    auto* pass = password_field("Passphrase", &dialog);
    auto* confirm = password_field("Repeat passphrase", &dialog);
    layout->addWidget(pass);
    layout->addWidget(confirm);

    QCheckBox* remember = nullptr;
    if (keychain::available()) {
        remember = remember_checkbox(&dialog);
        layout->addWidget(remember);
    }

    auto* error = error_label(&dialog);
    layout->addWidget(error);

    auto* buttons = new QHBoxLayout();
    buttons->addStretch();
    QPushButton* skip = nullptr;
    QPushButton* cancel = nullptr;
    if (allow_skip) {
        skip = new QPushButton("Skip (not recommended)", &dialog);
        buttons->addWidget(skip);
    } else {
        cancel = new QPushButton("Cancel", &dialog);
        buttons->addWidget(cancel);
    }
    auto* ok = new QPushButton(allow_skip ? "Protect my keys" : "Set passphrase", &dialog);
    ok->setDefault(true);
    buttons->addWidget(ok);
    layout->addLayout(buttons);

    PassphraseChoice result;
    QObject::connect(ok, &QPushButton::clicked, &dialog, [&] {
        const std::string typed = to_passphrase(pass->text());
        if (!KeyStore::is_acceptable_passphrase(typed)) {
            error->setText("Please use at least 8 characters. A few random words work well.");
            return;
        }
        if (typed != to_passphrase(confirm->text())) {
            error->setText("The two passphrases don't match.");
            return;
        }
        result.outcome = DialogOutcome::Accepted;
        result.passphrase = typed;
        result.remember = remember && remember->isChecked();
        dialog.accept();
    });
    if (skip) {
        QObject::connect(skip, &QPushButton::clicked, &dialog, [&] {
            result.outcome = DialogOutcome::Skipped;
            dialog.accept();
        });
    }
    if (cancel) QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);

    dialog.exec();
    return result;
}

PassphraseChoice ask_existing_passphrase(QWidget* parent, const QString& title, const QString& message,
                                         bool offer_remember, const QString& action_text) {
    QDialog dialog(parent);
    dialog.setWindowTitle(title);
    dialog.setMinimumWidth(420);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(text_label(message, &dialog));

    auto* pass = password_field("Passphrase", &dialog);
    layout->addWidget(pass);

    QCheckBox* remember = nullptr;
    if (offer_remember && keychain::available()) {
        remember = remember_checkbox(&dialog);
        layout->addWidget(remember);
    }

    auto* buttons = new QHBoxLayout();
    buttons->addStretch();
    auto* cancel = new QPushButton("Cancel", &dialog);
    auto* ok = new QPushButton(action_text, &dialog);
    ok->setDefault(true);
    buttons->addWidget(cancel);
    buttons->addWidget(ok);
    layout->addLayout(buttons);

    PassphraseChoice result;
    QObject::connect(ok, &QPushButton::clicked, &dialog, [&] {
        if (pass->text().isEmpty()) return;
        result.outcome = DialogOutcome::Accepted;
        result.passphrase = to_passphrase(pass->text());
        result.remember = remember && remember->isChecked();
        dialog.accept();
    });
    QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);

    dialog.exec();
    return result;
}
