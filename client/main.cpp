#include <QApplication>
#include "main_window.h"
#include "platform.h"

int main(int argc, char* argv[]) {
    platform_init();

    QApplication app(argc, argv);

    MainWindow window;
    window.show();

    int result = app.exec();

    platform_cleanup();
    return result;
}