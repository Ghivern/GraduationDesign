#ifndef HANDLE_H
#define HANDLE_H

#include <QObject>
#include "pcap.h"
#include "device.h"

class CapHandle:public QObject
{
    Q_OBJECT
public:
    CapHandle();
    ~CapHandle();

    //void CreatePcapHandle(QString devname);
    void CreatePcapHandle(qint32 index);

    //设置pcap_handle属性方法
    qint32 SetSnaplen(qint32 snap);
    qint32 SetPromisc(qint32 promisc);
    qint32 SetImmediateMode(qint32 immediateMode);

    //activate handle
    qint32 ActivateHandle();
    qint32 Activatehandle(qint32 index,qint32 snapLen = 65535,qint32 promisc = 1,qint32 immediateMode = 1);

    //获取pcap_handle
    pcap_t *GetPcapHandle();

    //获取链路层类型信息
    qint32 GetLinkType();
    QString GetLinkTypeName();
    QString GetLinkTypeDes();

    //获取设备信息
    qint32 GetDevIndex();
    QString GetDevname();

private:
    Device device;
    pcap_t *pcap_handle;
};

#endif // HANDLE_H
