#include "capture.h"

//Public Methods
Capture::Capture(qint32 devIndex)
{
    //新建handle,并设置属性
    this->capHandle = new CapHandle();
    this->capHandle->Activatehandle(devIndex);

    //新建存储抓取到包信息的List
    this->raw_packet_list = new raw_packet_list_t;
    this->packet_pkthdr_list = new packet_pkthdr_list_t;

    this->mutex = new QMutex();


}

Capture::~Capture(){

}

void Capture::StartCap(){
    //若列表中有数据，说明是重新开始，开启抓取时需要清除List
    if(this->raw_packet_list->length() != 0){
        this->raw_packet_list->clear();
        this->packet_pkthdr_list->clear();
    }
    this->canQuit = false;   //退出标志设为 false
    this->start();
}

void Capture::ChangeDeviceTo(qint32 devIndex){
    this->capHandle = new CapHandle();
    this->capHandle->Activatehandle(devIndex);
}

void Capture::StopCap(){
    this->canQuit = true;
}

raw_packet_list_t* Capture::GetListRaw(){
    return this->raw_packet_list;
}

packet_pkthdr_list_t* Capture::GetListInfo(){
    return this->packet_pkthdr_list;
}

CapHandle* Capture::GetHandle(){
    return this->capHandle;
}

QMutex* Capture::GetMutex(){
    return this->mutex;
}


//Protected Methods
void Capture::run(){
    qDebug() << "capture: capture thread start";
    const u_char *pRawPacket;
    struct pcap_pkthdr *pPacketInfo;
    qint64 No = 0;
    while(!this->canQuit){
        if( pcap_next_ex(this->capHandle->GetPcapHandle(),&pPacketInfo,&pRawPacket) == 1 ){
            struct pcap_pkthdr *packetInfo = new pcap_pkthdr;
            memcpy(packetInfo,pPacketInfo,sizeof(pcap_pkthdr));
            u_char *rawPacket = (u_char*)malloc(packetInfo->caplen);
            memcpy(rawPacket,pRawPacket,packetInfo->caplen);
            this->mutex->lock();
            this->raw_packet_list->append(rawPacket);
            this->packet_pkthdr_list->append(packetInfo);
            emit onePacketCaptured(No);
            No++;
            this->mutex->unlock();
        }else{
            qDebug() << "capture: capture one packet failed";
        }
    }
    qDebug() << "capture: capture thread start";
    quit();
}

void Capture::clear(){
    if(this->raw_packet_list->length() > 0)
        this->raw_packet_list->clear();
    if(packet_pkthdr_list->length() > 0)
        this->packet_pkthdr_list->clear();
}


