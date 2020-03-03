#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "../threads/capture.h"
#include "../threads/dissect.h"

#include <QPushButton>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    Capture *capture;
    Dissect *dissect;

    QPushButton *btn;

public slots:
    void printProtocolTree(tree_node_t *tree,qint32 level);
    void printDissectResult(dissect_result_t *res);

};
#endif // MAINWINDOW_H
