#include <QApplication>
#include <QMessageBox>

#include "main_window.h"
#include "platform.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("pq-file-transfer");
    QCoreApplication::setApplicationName("pq-client");

    if (platform_init() != 0) {
        QMessageBox::critical(nullptr, "PQ File Transfer", "Failed to initialize networking.");
        return 1;
    }

    int result = 0;
    {
        MainWindow window;  // destroyed (and its worker joined) before network cleanup
        window.show();
        result = app.exec();
    }

    platform_cleanup();
    return result;
}
