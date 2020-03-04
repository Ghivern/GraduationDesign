#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QPushButton"
#include "time.h"
#include "sys/time.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->capture = new Capture(0);
    this->dissect = new Dissect(this->capture);

    this->btn = new QPushButton("开始");
    this->setCentralWidget(btn);

    connect(this->btn,SIGNAL(clicked()),this->capture,SLOT(StartCap()));
    //connect(this->btn,SIGNAL(clicked()),this->dissect,SLOT(StartDissect()));

    connect(this->capture,SIGNAL(onePacketCaptured(qint64)),this->dissect,SLOT(DissectOnePacket(qint64)));

    connect(this->dissect,SIGNAL(print(dissect_result_t*)),this,SLOT(printDissectResult(dissect_result_t*)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::printProtocolTree(tree_node_t *tree,qint32 level){
   // qDebug() << "进入打印协议树方法";
    while(tree!=NULL){
        QString str;
        qint32 index = 0;
        while (index < level ) {
            if(level == 1)
                str += "@";
            else
                str += "=";
            index++;
        }
        qDebug() << str << tree->msg << "Start ~ End" << tree->start << "~" << tree->end;
        if( tree->nextFloor != NULL )
            printProtocolTree(tree->nextFloor,level + 5);
        tree = tree->next;
    }
}

void MainWindow::printDissectResult(dissect_result_t *res){
    //qDebug() << "进入打印方法";
    //打印简单解析结果
    qDebug() << res->No << "   " << res->TimeSinceFirstFrame << "   " << res->Source
             << "   "  << res->Destination << "   " << res->Protocol << "   "
             << res->Length  << "  " << res->Info;
    gettimeofday(&res->DisplayTime,NULL);

    //打印协议树
    info_for_detailed_dissect_t *info = new info_for_detailed_dissect_t;
    info->No = res->No;
    info->devName.append(QString(this->capture->GetHandle()->GetDevname()));
    info->devIndex = this->capture->GetHandle()->GetDevIndex();
    info->dataLinkVal = this->capture->GetHandle()->GetLinkType();
    info->dataLinkName.append(QString(this->capture->GetHandle()->GetLinkTypeName()));
    tree_node_t *tree = this->dissect->GetLoader()->GetDissecter(1)->dissect(
                this->capture->GetListRaw()->at(res->No)
                ,this->capture->GetListInfo()->at(res->No)
                ,this->dissect->GetDissectResList()
                ,info);

    this->printProtocolTree(tree,1);


    //打印原始数据
    qint64 index = 0;
    while(index < this->dissect->GetDissectResList()->at(info->No)->HeadersLen - 5){
        qDebug() << QString::asprintf(" %02x %02x %02x %02x %02x %02x"
                                      ,this->capture->GetListRaw()->at(res->No)[index]
                                      ,this->capture->GetListRaw()->at(res->No)[index+1]
                                      ,this->capture->GetListRaw()->at(res->No)[index+2]
                                      ,this->capture->GetListRaw()->at(res->No)[index+3]
                                      ,this->capture->GetListRaw()->at(res->No)[index+4]
                                      ,this->capture->GetListRaw()->at(res->No)[index+5]
                                      );
        index += 6;
    }
    qDebug() << "------------------------------------------------------------------------------------";
}



