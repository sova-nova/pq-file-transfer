#include "keychain.h"

#ifdef PQ_HAVE_KEYCHAIN

#include <QEventLoop>
#include <QObject>
#include <QString>

#include <qt6keychain/keychain.h>

namespace {

const char SERVICE[] = "pq-file-transfer";

// QtKeychain jobs are asynchronous; wait for completion with a local event loop. This is the
// pattern QtKeychain documents, and it keeps the window repainting while the OS may be
// showing its own unlock prompt.
template <typename Job>
bool run(Job& job) {
    QEventLoop loop;
    QObject::connect(&job, &QKeychain::Job::finished, &loop, &QEventLoop::quit);
    job.start();
    loop.exec();
    return job.error() == QKeychain::NoError;
}

}  // namespace

namespace keychain {

bool available() { return true; }

std::optional<std::string> load(const std::string& account) {
    QKeychain::ReadPasswordJob job{QString::fromLatin1(SERVICE)};
    job.setAutoDelete(false);
    job.setKey(QString::fromStdString(account));
    if (!run(job)) return std::nullopt;
    const QString text = job.textData();
    if (text.isEmpty()) return std::nullopt;
    return text.toStdString();
}

bool store(const std::string& account, const std::string& secret) {
    QKeychain::WritePasswordJob job{QString::fromLatin1(SERVICE)};
    job.setAutoDelete(false);
    job.setKey(QString::fromStdString(account));
    job.setTextData(QString::fromStdString(secret));
    return run(job);
}

bool remove(const std::string& account) {
    QKeychain::DeletePasswordJob job{QString::fromLatin1(SERVICE)};
    job.setAutoDelete(false);
    job.setKey(QString::fromStdString(account));
    run(job);
    return job.error() == QKeychain::NoError || job.error() == QKeychain::EntryNotFound;
}

}  // namespace keychain

#else  // built without QtKeychain

namespace keychain {

bool available() { return false; }
std::optional<std::string> load(const std::string&) { return std::nullopt; }
bool store(const std::string&, const std::string&) { return false; }
bool remove(const std::string&) { return true; }

}  // namespace keychain

#endif
