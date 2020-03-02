#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    qDebug() << "测试";
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
