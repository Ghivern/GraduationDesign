#include "dissecter_udp.h"

bool Dissecter_udp::udp_valitation = false;
QHash<QString,qint64> Dissecter_udp::streamIndex;

void Dissecter_udp::dissect_udp(const udp_hdr *udp//const u_char *packet
                                , dissect_result_list_t *dissect_result_list
                                , tree_node_t *tree
                                , info_for_detailed_dissect_t *info){
    if( info != NULL ){
        tree =  DTree::addNext(tree,udp_msg_top_level(udp),udp_p_top_level_start(),udp_p_top_level_end());  // - 添加UDP顶层
        tree_node_t *nextF = DTree::addNextFloor(tree,udp_msg_src_port(udp),udp_p_src_port_start(),udp_p_src_port_end());  // - - 添加 SRC PORT
        nextF = DTree::addNext(nextF,udp_msg_dst_port(udp),udp_p_dst_port_start(),udp_p_dst_port_end());  //  - - 添加 DST PORT
        nextF = DTree::addNext(nextF,udp_msg_length(udp),udp_p_length_start(),udp_p_length_end());   // - -添加 LENGTH
        nextF = DTree::addNext(nextF,udp_msg_check_sum(udp),udp_p_check_sum_start(),udp_p_check_sum_end());   //  - -添加 Checksum
        nextF = DTree::addNext(nextF,udp_msg_check_sum_status(udp));    // - - 添加 Checksum status

        //添加Stream Index
        QString msg = "[ Stream Index :";
        QString key1 = dissect_result_list->at(info->No)->Source
                + QString::asprintf("%u",udp_get_src_port(udp))
                + dissect_result_list->at(info->No)->Destination
                + QString::asprintf("%u",udp_get_dst_port(udp));
        QString key2 = dissect_result_list->at(info->No)->Destination
                + QString::asprintf("%u",udp_get_dst_port(udp))
                + dissect_result_list->at(info->No)->Source
                + QString::asprintf("%u",udp_get_src_port(udp));
        if(Dissecter_udp::streamIndex.contains(key1))
            msg.append( QString::asprintf("%lld ]",Dissecter_udp::streamIndex.value(key1)) );
        else if(Dissecter_udp::streamIndex.contains(key2))
            msg.append( QString::asprintf("%lld ]",Dissecter_udp::streamIndex.value(key2)) );
        else
            msg.append( QString::asprintf("x ]"));
        nextF = DTree::addNext(nextF,msg);
    }else{// 简单解析 NO,Time,Length(Frame)     ,Src,Dst,(IP/MAC)     Protocol,Info(顶层协议)  protocolStack,headersLen(每曾均处理)
        dissect_result_list->back()->srcPort = udp_get_src_port(udp);
        dissect_result_list->back()->dstPort = udp_get_dst_port(udp);
        dissect_result_list->back()->HeadersLen += sizeof (udp_hdr);
        dissect_result_list->back()->protocolStack.append("UDP");
        QString info = QString::asprintf("%d --> %d",ntohs(udp->sport),ntohs(udp->dport));
        dissect_result_list->back()->Info.append(info);
        dissect_result_list->back()->Protocol.append("UDP");

        //处理Stream Index
        QString key1 = dissect_result_list->back()->Source
                + QString::asprintf("%u",udp_get_src_port(udp))
                + dissect_result_list->back()->Destination
                + QString::asprintf("%u",udp_get_dst_port(udp));
        QString key2 = dissect_result_list->back()->Destination
                + QString::asprintf("%u",udp_get_dst_port(udp))
                + dissect_result_list->back()->Source
                + QString::asprintf("%u",udp_get_src_port(udp));
        if(Dissecter_udp::streamIndex.contains(key1)){
                ;
        }else if(Dissecter_udp::streamIndex.contains(key2)){
                ;
        }else{
            Dissecter_udp::streamIndex.insert(key1, Dissecter_udp::streamIndex.keys().length());
        }

    }
}


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ others
void Dissecter_udp::SetValitation(bool v){
    Dissecter_udp::udp_valitation = v;
}

bool Dissecter_udp::GetValitation(){
    return Dissecter_udp::udp_valitation;
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  get 方法
ushort Dissecter_udp::udp_get_src_port(const udp_hdr *header){
    return ntohs(header->sport);
}

ushort Dissecter_udp::udp_get_dst_port(const udp_hdr *header){
    return ntohs(header->dport);
}

ushort Dissecter_udp::udp_get_length(const udp_hdr *header){
    return ntohs(header->tot_len);
}

ushort Dissecter_udp::udp_get_check_sum(const udp_hdr *header){
    return ntohs(header->check_sum);
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  msg 方法
QString Dissecter_udp::udp_msg_top_level(const udp_hdr *header){
    return
            QString::asprintf("User Datagram Protocol , Src Port : %d , Dst Port : %d "
                              ,udp_get_src_port(header)
                              ,udp_get_dst_port(header)
                );
}

QString Dissecter_udp::udp_msg_src_port(const udp_hdr *header){
    return
            QString::asprintf("Source Port : %d ",udp_get_src_port(header));
}

QString Dissecter_udp::udp_msg_dst_port(const udp_hdr *header){
    return
            QString::asprintf("Destination Port : %d ",udp_get_dst_port(header));
}

QString Dissecter_udp::udp_msg_length(const udp_hdr *header){
    return
            QString::asprintf("Length : %d ",udp_get_length(header));
}

QString Dissecter_udp::udp_msg_check_sum(const udp_hdr *header){
    ushort cs = udp_get_check_sum(header);
    return
            QString::asprintf("Checksum : %02x%02x",((uchar*)&cs)[1],((uchar*)&cs)[0]) + (GetValitation() ? "[ Verified ]":"Unverified");
}

QString Dissecter_udp::udp_msg_check_sum_status(const udp_hdr *header){
    Q_UNUSED(header)
    QString str = "[ Checksum Status : ";
    if(GetValitation()){
        str += "Verified ]";
    }else{
        str+= "Unverified ]";
    }
    return str;
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  p 方法
qint32 Dissecter_udp::udp_p_top_level_start(){
    return sizeof (eth_hdr) + sizeof (ip_hdr);
}

qint32 Dissecter_udp::udp_p_src_port_start(){
    return udp_p_top_level_start();
}

qint32 Dissecter_udp::udp_p_dst_port_start(){
    return udp_p_src_port_start() + UDP_LENS::SRC_PORT;
}

qint32 Dissecter_udp::udp_p_length_start(){
    return udp_p_dst_port_start() + UDP_LENS::DST_PORT;
}

qint32 Dissecter_udp::udp_p_check_sum_start(){
    return udp_p_length_start() + UDP_LENS::LENGTH;
}

qint32 Dissecter_udp::udp_p_top_level_end(){
    return udp_p_check_sum_start() + UDP_LENS::CHECK_SUM - 1;
}

qint32 Dissecter_udp::udp_p_src_port_end(){
    return udp_p_dst_port_start() - 1;
}

qint32 Dissecter_udp::udp_p_dst_port_end(){
    return udp_p_length_start() - 1;
}

qint32 Dissecter_udp::udp_p_length_end(){
    return udp_p_check_sum_start() - 1;
}

qint32 Dissecter_udp::udp_p_check_sum_end(){
    return udp_p_top_level_end();
}
