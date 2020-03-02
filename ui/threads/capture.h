#ifndef CAPTURE_H
#define CAPTURE_H

#include <QObject>
#include <QThread>
#include <QMutex>
#include "../global/global.h"
#include "../caphandle.h"
#include "../device.h"


class Capture:public QThread
{
    Q_OBJECT
public:
    Capture(qint32 devIndex);
    ~Capture();

    void ChangeDeviceTo(qint32 devIndex);


    raw_packet_list_t* GetListRaw();
    packet_pkthdr_list_t* GetListInfo();
    CapHandle* GetHandle();
    QMutex *GetMutex();



protected:
    void run() Q_DECL_OVERRIDE;
    void clear();   //在重新开始前，PLRaw、PLInfo


private:
    QMutex *mutex;
    bool canQuit;  //线程退出标志
    CapHandle *capHandle;
    raw_packet_list_t *raw_packet_list;
    packet_pkthdr_list_t *packet_pkthdr_list;

public slots:
    void StartCap();
    void StopCap();
};

#endif // CAPTURE_H
