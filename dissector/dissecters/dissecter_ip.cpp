#include "dissecter_ip.h"

bool Dissecter_ip::ip_valitation = false;

void Dissecter_ip::dissect_ip(const ip_hdr *ip//const u_char *packet
                              , dissect_result_list_t *dissect_result_list
                              , tree_node_t *tree
                              , info_for_detailed_dissect_t *info){
    if( info != NULL){   //详细解析   >>  处理协议树   >>  增加ip曾
        QString msg;
        tree =  DTree::addNext(tree,ip_msg_top_level(ip),ip_p_top_level_start(),ip_p_top_level_end());  // -  增加IP顶层

        tree_node_t* nextF = DTree::addNextFloor(tree,ip_msg_version(ip),ip_p_version_and_header_len_start(),ip_p_version_and_header_len_end());   // - -  增加Version
        nextF = DTree::addNext(nextF,ip_msg_header_length(ip),ip_p_version_and_header_len_start(),ip_p_version_and_header_len_end());  // - -  增加Header Len
        nextF = DTree::addNext(nextF,ip_msg_DS(ip),ip_p_tos_start(),ip_p_tos_end());  // - - 增加 DS Field
        tree_node_t *nextFF = DTree::addNextFloor(nextF,ip_msg_DSCP(ip),ip_p_tos_start(),ip_p_tos_end());  // - - -增加 DSCP
        nextFF = DTree::addNext(nextFF,ip_msg_ECN(ip),ip_p_tos_start(),ip_p_tos_end());  // - - - z增加 ECN
        nextF = DTree::addNext(nextF,ip_msg_total_length(ip),ip_p_total_len_start(),ip_p_total_len_end());   // - - 增加 total length
        nextF = DTree::addNext(nextF,ip_msg_identification(ip),ip_p_ident_start(),ip_p_ident_end());  // - -增加 Identification
        nextF = DTree::addNext(nextF,ip_msg_flags_and_offset(ip),ip_p_flags_and_offset_start(),ip_p_flags_and_offset_end());  //  - - 增加 frame and offset
        nextFF = DTree::addNextFloor(nextF,ip_msg_reserved_bit(ip),ip_p_flags_and_offset_start(),ip_p_flags_and_offset_end());  // - - - 增加reserved bit
        nextFF = DTree::addNext(nextFF,ip_msg_DF(ip),ip_p_flags_and_offset_start(),ip_p_flags_and_offset_end());       // - - - 增加 DF bit
        nextFF = DTree::addNext(nextFF,ip_msg_MF(ip),ip_p_flags_and_offset_start(),ip_p_flags_and_offset_end());       // - - - 增加 MF bit
        nextFF = DTree::addNext(nextFF,ip_msg_offset(ip),ip_p_flags_and_offset_start(),ip_p_flags_and_offset_end());   // - - - 增加 Offset
        nextF = DTree::addNext(nextF,ip_msg_ttl(ip),ip_p_ttl_start(),ip_p_ttl_end());  // - -  添加ttl
        nextF = DTree::addNext(nextF,ip_msg_protocol(ip),ip_p_protocol_start(),ip_p_protocol_end());   //  - -  添加protocol
        nextF = DTree::addNext(nextF,ip_msg_header_checksum(ip),ip_p_checksum_start(),ip_p_checksum_end());   //  - - 添加 header checksum
        nextF = DTree::addNext(nextF,ip_msg_header_checksum_status(ip));   // - - 增加 header checksum status
        nextF = DTree::addNext(nextF,ip_msg_address(ip,SD::SRC),ip_p_source_start(),ip_p_source_end());   // - -添加 Source address
        nextF = DTree::addNext(nextF,ip_msg_address(ip,SD::DST),ip_p_destination_start(),ip_p_destination_end());   // - -添加 Destination address
        //info->protocols.append("IP");    //为protocols增加成员
    }else{ // 简单解析 NO,Time,Length(Frame)     ,Src,Dst,(IP/MAC)     Protocol,Info(顶层协议)  protocolStack,headersLen(每曾均处理)
        dissect_result_list->back()->HeadersLen += sizeof (ip_hdr);
        dissect_result_list->back()->protocolStack.append("IP");
        dissect_result_list->back()->Source.append( ip_get_address(ip,SD::SRC));
        dissect_result_list->back()->Destination.append(ip_get_address(ip,SD::DST));
    }

    switch (ip_get_type(ip)) {
        case 6:
            Dissecter_tcp::dissect_tcp(ip_get_tcp_header(ip),dissect_result_list,tree,info);  //TCP
            break;
        case 17:
            Dissecter_udp::dissect_udp(ip_get_udp_header(ip),dissect_result_list,tree,info);   //UDP
            break;
        default:
            {
                dissect_result_list->back()->Protocol.append(ip_get_type_name(ip));
                dissect_result_list->back()->Info.append(QString::asprintf("有待添加解析器的协议号为%d",ip_get_type(ip)));
            }
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  others

void Dissecter_ip::SetValitation(bool v){
    Dissecter_ip::ip_valitation = v;
}

bool Dissecter_ip::GetValitation(){
    return Dissecter_ip::ip_valitation;
}


//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  get方法
tcp_hdr* Dissecter_ip::ip_get_tcp_header(const ip_hdr *ip){
    return (tcp_hdr*)((uchar*)ip + ip_get_header_length(ip));
}

udp_hdr* Dissecter_ip::ip_get_udp_header(const ip_hdr *ip){
    return (udp_hdr*)((uchar*)ip + ip_get_header_length(ip));
}






QString Dissecter_ip::ip_get_address(const ip_hdr *header,SD sd){
    if(sd == SD::SRC){
        return
            QString::asprintf("%d.%d.%d.%d"
            ,header->sourceIP[0]
            ,header->sourceIP[1]
            ,header->sourceIP[2]
            ,header->sourceIP[3]
            );
    }else{
        return
            QString::asprintf("%d.%d.%d.%d"
            ,header->destIP[0]
            ,header->destIP[1]
            ,header->destIP[2]
            ,header->destIP[3]
            );
    }
}

uchar Dissecter_ip::ip_get_type(const ip_hdr *header){
    return header->protocol;
}

QString Dissecter_ip::ip_get_type_name(const ip_hdr *header){
    switch (ip_get_type(header)) {
    case (uchar)0x06:
        return "TCP";
    case (uchar)0x11:
        return  "UDP";
    default:
        return  "IP携带的是其他类型协议数据包";
    }
}

uchar Dissecter_ip::ip_get_version(const ip_hdr *header){
    return (header->versionAndHeaderLen & 0xf0) >> 4;
}

uchar Dissecter_ip::ip_get_header_length(const ip_hdr *header){
    return (header->versionAndHeaderLen & 0x0f);
}

uchar Dissecter_ip::ip_get_DS(const ip_hdr *header){
    return header->tos;
}

uchar Dissecter_ip::ip_get_DSCP(const ip_hdr *header){
    return  header->tos >> 2;
}

uchar Dissecter_ip::ip_get_ECN(const ip_hdr *header){
    return header->tos & 0x03;
}

ushort Dissecter_ip::ip_get_total_length(const ip_hdr *header){
    return ntohs(header->total_len);
}

ushort Dissecter_ip::ip_get_identification(const ip_hdr *header){
    return ntohs(header->ident);
}

ushort Dissecter_ip::ip_get_flags_and_offset(const ip_hdr *header){
    return ntohs(header->flagsAndOffest);
}

uchar Dissecter_ip::ip_get_flags_reserved_bit(const ip_hdr *header){
    ushort flags_and_offset = ip_get_flags_and_offset(header);
    return  (uchar)((flags_and_offset & 0x8000) >> 15);
}

uchar Dissecter_ip::ip_get_flags_DF(const ip_hdr *header){
    ushort flags_and_offset = ip_get_flags_and_offset(header);
    return  (uchar)((flags_and_offset & 0x4000) >> 14);
}

uchar Dissecter_ip::ip_get_flags_MF(const ip_hdr *header){
    ushort flags_and_offset = ip_get_flags_and_offset(header);
    return  (uchar)((flags_and_offset & 0x2000) >> 13);
}

ushort Dissecter_ip::ip_get_offset(const ip_hdr *header){
    return ip_get_flags_and_offset(header) & 0x1fff;
}

uchar Dissecter_ip::ip_get_ttl(const ip_hdr *header){
    return header->ttl;
}

ushort Dissecter_ip::ip_get_header_checksum(const ip_hdr *header){
    return ntohs(header->checksum);
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  msg方法
QString Dissecter_ip::ip_msg_top_level(const ip_hdr *header){
    return
        QString::asprintf("Internet Protocol Version %d , Src: ",ip_get_version(header))
                    + ip_get_address(header,SD::SRC)
                    + QString::asprintf(" , Det: ") + ip_get_address(header,SD::DST);
}

QString Dissecter_ip::ip_msg_version(const ip_hdr *header){
    uchar version = ip_get_version(header);
    return
         QString::asprintf("%d%d%d%d .... = Version: %d"
                        ,(version & 0x08) >> 3
                        ,(version & 0x04) >> 2
                        ,(version & 0x02) >> 1
                        ,( version & 0x01),
                        ip_get_version(header)
                );
}

QString Dissecter_ip::ip_msg_header_length(const ip_hdr *header){
    uchar headerLen = ip_get_header_length(header);
    return
         QString::asprintf(".... %d%d%d%d = Header Length: %d bytes (%d)"
                        ,(headerLen & 0x08) >> 3
                        ,(headerLen & 0x04) >> 2
                        ,(headerLen & 0x02) >> 1
                        ,(headerLen & 0x01)
                        ,ip_get_header_length(header) * 4
                        ,ip_get_header_length(header)
                );
}

QString Dissecter_ip::ip_msg_DS(const ip_hdr *header){
    return  QString::asprintf("Differentiated Services Field : 0x%02x",ip_get_DS(header));
}

QString Dissecter_ip::ip_msg_DSCP(const ip_hdr *header){
    uchar dscp = ip_get_DSCP(header);
    return QString::asprintf("%d%d%d%d %d%d.. = Differentiated Services Codepoint"
                              ,(dscp & 0x20 >> 5)
                              ,(dscp & 0x10 >> 4)
                              ,(dscp & 0x08 >> 3)
                              ,(dscp & 0x04 >> 2)
                              ,(dscp & 0x02 >> 1)
                              ,(dscp & 0x01 >> 0)
                         );
}

QString Dissecter_ip::ip_msg_ECN(const ip_hdr *header){
    uchar ecn = ip_get_ECN(header);
    return QString::asprintf(".... ..%d%d = Explicit Congestion Notification"
                             ,(ecn & 0x02) >> 1
                             ,(ecn & 0x01) >> 0
                         );
}

QString Dissecter_ip::ip_msg_total_length(const ip_hdr *header){
    return QString::asprintf("Total Length: %d",ip_get_total_length(header));
}

QString Dissecter_ip::ip_msg_identification(const ip_hdr *header){
    ushort ident = ip_get_identification(header);
    return QString::asprintf("Identification : %02x%02x (%d)",((uchar*)&ident)[1],((uchar*)&ident)[0],ident);
}

QString Dissecter_ip::ip_msg_flags_and_offset(const ip_hdr *header){
    ushort flag_and_offset = ip_get_flags_and_offset(header);
    return QString::asprintf("0x%02x%02x "
                                    ,((uchar*)&flag_and_offset)[1]
                                    ,((uchar*)&flag_and_offset)[0]
                            )
                            + (ip_get_flags_DF(header) == 1 ? ", Don't fragment":"");
}

QString Dissecter_ip::ip_msg_reserved_bit(const ip_hdr *header){
    uchar bit = ip_get_flags_reserved_bit(header);
    return QString::asprintf("%d... .... .... .... = Reserved bit : ",bit)
            + (bit == 1 ? "Set" : "Not Set");
}

QString Dissecter_ip::ip_msg_MF(const ip_hdr *header){
    uchar bit = ip_get_flags_MF(header);
    return QString::asprintf("..%d. .... .... .... = More fragments : ",bit)
            + (bit == 1 ? "Set" : "Not Set");
}

QString Dissecter_ip::ip_msg_DF(const ip_hdr *header){
    uchar bit = ip_get_flags_DF(header);
    return QString::asprintf(".%d.. .... .... .... = Don't fragment : ",bit)
            + (bit == 1 ? "Set" : "Not Set");
}

QString Dissecter_ip::ip_msg_offset(const ip_hdr *header){
    ushort bits = ip_get_offset(header);
    return QString::asprintf("...%d %d%d%d%d %d%d%d%d %d%d%d%d = Fragment offset : %d"
                             ,(bits & 0x1000) >> 12
                             ,(bits & 0x0800) >> 11
                             ,(bits & 0x0400) >> 10
                             ,(bits & 0x0200) >> 9
                             ,(bits & 0x0100) >> 8
                             ,(bits & 0x0080) >> 7
                             ,(bits & 0x0040) >> 6
                             ,(bits & 0x0020) >> 5
                             ,(bits & 0x0010) >> 4
                             ,(bits & 0x0008) >> 3
                             ,(bits & 0x0004) >> 2
                             ,(bits & 0x0002) >> 1
                             ,(bits & 0x0001) >> 0
                             ,bits
                             );
}

QString Dissecter_ip::ip_msg_ttl(const ip_hdr *header){
    return QString::asprintf("Time to live : %d",ip_get_ttl(header));
}

QString Dissecter_ip::ip_msg_protocol(const ip_hdr *header){
    return QString("Protocol : ") + ip_get_type_name(header) + QString::asprintf("(%d)",ip_get_type(header));
}

QString Dissecter_ip::ip_msg_header_checksum(const ip_hdr *header){
    ushort cs = ip_get_header_checksum(header);
    return QString::asprintf("Header checksum : 0x%02x%02x  [ validation ",((uchar*)&cs)[1],((uchar*)&cs)[0])
            + (Dissecter_ip::GetValitation() ? "]":"disabled ]");
}

QString Dissecter_ip::ip_msg_header_checksum_status(const ip_hdr *header){
    Q_UNUSED(header)
    QString str = "[ Header checksum status : ";
    if(Dissecter_ip::GetValitation()){
        str += "Verified ]";
        // 增加检验代码，根据检验结果，赋予相应值
    }else{
        str += "Unverified ]";
    }
    return str;
}

QString Dissecter_ip::ip_msg_address(const ip_hdr *header, SD sd){
    QString str;
    if(sd == SD::SRC){
        str = "Source : ";
    }else{
        str = "Destination : ";
    }
    return str + ip_get_address(header,sd);
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   p方法
qint32 Dissecter_ip::ip_p_top_level_start(){
    return sizeof(eth_hdr);
}

qint32 Dissecter_ip::ip_p_version_and_header_len_start(){
    return ip_p_top_level_start();
}

qint32 Dissecter_ip::ip_p_tos_start(){
    return ip_p_version_and_header_len_start() + IP_LENS::VERSION_ANDH_EADERLENGTH;
}

qint32 Dissecter_ip::ip_p_total_len_start(){
    return ip_p_tos_start() + IP_LENS::TOS;
}

qint32 Dissecter_ip::ip_p_ident_start(){
    return ip_p_total_len_start() + IP_LENS::TOTALLEN;
}

qint32 Dissecter_ip::ip_p_flags_and_offset_start(){
    return ip_p_ident_start() + IP_LENS::IDENT;
}

qint32 Dissecter_ip::ip_p_ttl_start(){
    return ip_p_flags_and_offset_start() + IP_LENS::FLAGS_AND_OFFSET;
}

qint32 Dissecter_ip::ip_p_protocol_start(){
    return ip_p_ttl_start() + IP_LENS::TTL;
}

qint32 Dissecter_ip::ip_p_checksum_start(){
    return ip_p_protocol_start() + IP_LENS::PROTOCOL;
}

qint32 Dissecter_ip::ip_p_source_start(){
    return ip_p_checksum_start() + IP_LENS::CHECKSUM;
}

qint32 Dissecter_ip::ip_p_destination_start(){
    return ip_p_source_start() + IP_LENS::SOURCEIP;
}

qint32 Dissecter_ip::ip_p_top_level_end(){
    return  ip_p_destination_start() + IP_LENS::DESTIP - 1;
}

qint32 Dissecter_ip::ip_p_version_and_header_len_end(){
    return  ip_p_version_and_header_len_start() + IP_LENS::VERSION_ANDH_EADERLENGTH - 1;
}

qint32 Dissecter_ip::ip_p_tos_end(){
    return ip_p_tos_start() + IP_LENS::TOS - 1;
}

qint32 Dissecter_ip::ip_p_total_len_end(){
    return ip_p_total_len_start() + IP_LENS::TOTALLEN - 1;
}

qint32 Dissecter_ip::ip_p_ident_end(){
    return ip_p_ident_start() + IP_LENS::IDENT - 1;
}

qint32 Dissecter_ip::ip_p_flags_and_offset_end(){
    return ip_p_flags_and_offset_start() + IP_LENS::FLAGS_AND_OFFSET - 1;
}

qint32 Dissecter_ip::ip_p_ttl_end(){
    return ip_p_ttl_start() + IP_LENS::TTL - 1;
}

qint32 Dissecter_ip::ip_p_protocol_end(){
    return ip_p_protocol_start() + IP_LENS::PROTOCOL - 1;
}

qint32 Dissecter_ip::ip_p_checksum_end(){
    return ip_p_checksum_start() + IP_LENS::CHECKSUM - 1;
}

qint32 Dissecter_ip::ip_p_source_end(){
    return ip_p_source_start() + IP_LENS::SOURCEIP - 1;
}

qint32 Dissecter_ip::ip_p_destination_end(){
    return  ip_p_destination_start() + IP_LENS::DESTIP - 1;
}

