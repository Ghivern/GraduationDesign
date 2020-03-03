#include "device.h"
#include <QDebug>

Device::Device()
{
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&devs,errbuf) == -1){
        qDebug() << QLatin1String(errbuf);
    }else{
        while(devs != NULL){
            this->device_list.append(devs);
            devs = devs->next;
        }
    }
    this->currentDevIndex = -1;
}

Device::~Device(){
    if(!this->device_list.isEmpty())
        pcap_freealldevs(this->device_list.at(0));
}

QString Device::GetDeviceNameByIndex(qint32 index){
    return QLatin1String(this->device_list[index]->name);
}

qint32 Device::GetDeviceCount(){
    return this->device_list.length();
}

void Device::SetCurrentDevIndex(qint32 index){
    this->currentDevIndex = index;
}

qint32 Device::GetCurrentDevIndex(){
    return this->currentDevIndex;
}

QString Device::GetCurrentDevName(){
    if(this->currentDevIndex > 0 && this->GetDeviceCount() < this->device_list.length())
        return QLatin1String(this->device_list[this->currentDevIndex]->name);
    else
        return "";
}
