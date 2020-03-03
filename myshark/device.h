#ifndef DEVICES_H
#define DEVICES_H

#include <QObject>
#include "../global.h"

class Device:public QObject
{
    Q_OBJECT

public:
    Device();
    ~Device();

    QString GetDeviceNameByIndex(qint32 index);  //通过index获取设备名称
    qint32 GetDeviceCount();  //获取设备数量

    void SetCurrentDevIndex(qint32 index);
    QString GetCurrentDevName();
    qint32 GetCurrentDevIndex();
private:
    device_list_t device_list;
    qint32 currentDevIndex;

};

#endif // DEVICES_H
