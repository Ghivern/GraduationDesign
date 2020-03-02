#include "dissecter_tcp.h"

QHash<QString,qint64> Dissecter_tcp::streamIndex;

void Dissecter_tcp::dissect_tcp(const tcp_hdr *tcp//const u_char *packet
                                , dissect_result_list_t *dissect_result_list
                                , tree_node_t *tree
                                , info_for_detailed_dissect_t *info){
    if(info != NULL){
        QString msg = QString(
                    QString::asprintf("Transmission Control Protocol , Src Port: %d ,"
                                       " Dst Port: %d , seq: %u , ack : %u , ACK : %u , HeaderLen : %d , PayLoad Len : %d"
                                      ,tcp_get_src_port(tcp)
                                      ,tcp_get_dst_port(tcp)
                                      ,tcp_get_seq(tcp)
                                      ,tcp_get_ack(tcp)
                                      ,tcp_get_ACK(tcp)
                                      ,tcp_get_header_len(tcp)
                                      ,tcp_get_payload_len(tcp,dissect_result_list->at(info->No)->Length))
                     );
        tree =  DTree::addNext(tree,msg);
    }
    else// 简单解析 NO,Time,Length(Frame)     ,Src,Dst,(IP/MAC)     Protocol,Info(顶层协议)  protocolStack,headersLen(每曾均处理)
    {
       dissect_result_list->back()->HeadersLen += sizeof (tcp_hdr);
       dissect_result_list->back()->protocolStack.append("TCP");
       QString info = QString::asprintf("%d --> %d",ntohs(tcp->sport),ntohs(tcp->dport));
       dissect_result_list->back()->Info.clear();
       dissect_result_list->back()->Info.append(QString(info));
       dissect_result_list->back()->Protocol.clear();
       dissect_result_list->back()->Protocol.append(QString("TCP"));

//       //处理streamIndex计数器
//       if(dissect_result_list->length() == 1){
//           Dissecter_tcp::streamIndex.clear();
//           Dissecter_tcp::streamIndex.insert("srcdstsrcdst",1);
//       }else{
//           if(Dissecter_tcp::streamIndex.contains("s")){
//               (*Dissecter_tcp::streamIndex.find("s"))++;
//           }else{
//               Dissecter_tcp::streamIndex.insert("new",1);
//           }
//       }
    }
}


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ get方法
ushort Dissecter_tcp::tcp_get_src_port(const tcp_hdr *header){
    return ntohs(header->sport);
}

ushort Dissecter_tcp::tcp_get_dst_port(const tcp_hdr *header){
    return ntohs(header->dport);
}

uint Dissecter_tcp::tcp_get_seq(const tcp_hdr *header){
    return ntohl(header->seq);
}

uint Dissecter_tcp::tcp_get_ack(const tcp_hdr *header){
    return ntohl(header->ack);
}

uchar Dissecter_tcp::tcp_get_header_len(const tcp_hdr *header){
    return 4 * ((header->offsetAndRes & 0xfc) >> 4);
}

ushort Dissecter_tcp::tcp_get_payload_len(const tcp_hdr *header,qint16 caplen){
    return caplen - sizeof(eth_hdr) - sizeof (ip_hdr) - tcp_get_header_len(header);
}

uchar Dissecter_tcp::tcp_get_URG(const tcp_hdr *header){
    return (header->resAndFlags & 0x20) >> 5;
}

uchar Dissecter_tcp::tcp_get_ACK(const tcp_hdr *header){
    return (header->resAndFlags & 0x10) >> 4;
}

uchar Dissecter_tcp::tcp_get_PSH(const tcp_hdr *header){
    return (header->resAndFlags & 0x08) >> 3;
}

uchar Dissecter_tcp::tcp_get_RST(const tcp_hdr *header){
    return (header->resAndFlags & 0x04 ) >> 2;
}

uchar Dissecter_tcp::tcp_get_SYN(const tcp_hdr *header){
    return (header->resAndFlags & 0x02 ) >> 1;
}

uchar Dissecter_tcp::tcp_get_FIN(const tcp_hdr *header){
    return (header->resAndFlags & 0x01 ) >> 0;
}
