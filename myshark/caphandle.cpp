#include "caphandle.h"
#include <QDebug>

//Public Methods
CapHandle::CapHandle()
{
    this->pcap_handle = NULL;
}

CapHandle::~CapHandle(){

}

void CapHandle::CreatePcapHandle(qint32 index){
    char errbuf[PCAP_ERRBUF_SIZE];
    this->pcap_handle = pcap_create(this->device.GetDeviceNameByIndex(index).toLatin1(),errbuf);
    if( this->pcap_handle == NULL ){
        qDebug() << QLatin1String(errbuf);
        qDebug() << "Handle: handle is NULL";
    }
    this->device.SetCurrentDevIndex(index);
    qDebug() << "Handle: handle create success";
}

qint32 CapHandle::SetSnaplen(qint32 snap){
    return pcap_set_snaplen(this->pcap_handle,snap);
}

qint32 CapHandle::SetPromisc(qint32 promisc){
    return pcap_set_promisc(this->pcap_handle,promisc);
}

qint32 CapHandle::SetImmediateMode(qint32 immediateMode){
    return pcap_set_immediate_mode(this->pcap_handle,immediateMode);
}

qint32 CapHandle::ActivateHandle(){
    if( pcap_activate(this->pcap_handle) < 0){
        qDebug() << QLatin1String(pcap_geterr(this->pcap_handle));
        qDebug() << "Handle： handle activate failed";
        return -1;
    }
    qDebug() << "handle activate activate success";
    return 0;
}

qint32 CapHandle::Activatehandle(qint32 index,qint32 snapLen,qint32 promisc,qint32 immediateMode ){
    this->CreatePcapHandle(index);
    this->SetPromisc(promisc);
    this->SetSnaplen(snapLen);
    this->SetImmediateMode(immediateMode);
    return this->ActivateHandle();
}

pcap_t* CapHandle::GetPcapHandle(){
    return this->pcap_handle;
}

qint32 CapHandle::GetLinkType(){
    return pcap_datalink(this->pcap_handle);
}

QString CapHandle::GetLinkTypeName(){
    return pcap_datalink_val_to_name( pcap_datalink(this->pcap_handle) );
}

QString CapHandle::GetLinkTypeDes(){
    return pcap_datalink_val_to_description( pcap_datalink(this->pcap_handle) );
}

QString CapHandle::GetDevname(){
    return this->device.GetCurrentDevName();
}

qint32 CapHandle::GetDevIndex(){
    return this->device.GetCurrentDevIndex();
}

