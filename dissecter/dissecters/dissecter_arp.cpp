#include "dissecter_arp.h"


void Dissecter_arp::dissect_arp(const arp_hdr *arp//const u_char *packet
                 ,dissect_result_list_t *dissect_result_list
                 ,tree_node_t *tree
                 ,info_for_detailed_dissect_t *info){
    if(info != NULL){
        tree = DTree::addNext(tree,arp_msg_top_level(arp),arp_p_top_level_start(),arp_p_top_level_end());  // -  添加ARP顶层
        tree_node_t *treeF = DTree::addNextFloor(tree,arp_msg_hardware_type(arp),arp_p_hardware_type_start(),arp_p_hardware_type_end());  // - -添加Hardware type
        treeF = DTree::addNext(treeF,arp_msg_protocol_type(arp),arp_p_protocol_type_start(),arp_p_protocol_type_end());  // - -  添加Protocol type曾
        treeF = DTree::addNext(treeF,arp_msg_hardware_size(arp),arp_p_hardware_address_len_start(),arp_p_hardware_address_len_end());  // - - 添加Hardware size
        treeF = DTree::addNext(treeF,arp_msg_protocol_size(arp),arp_p_protocol_address_len_start(),arp_p_protocol_address_len_end());  // - - 添加Protocol size曾
        treeF = DTree::addNext(treeF,arp_msg_op_code(arp),arp_p_opcode_start(),arp_p_opcode_end());     // - - 添加 Opcode曾
        treeF = DTree::addNext(treeF,arp_msg_hardware_address(arp,SD::SRC),arp_p_src_hardware_address_start(),arp_p_src_hardware_address_end());  // - - 曾加Sender mac address
        treeF = DTree::addNext(treeF,arp_msg_protocol_address(arp,SD::SRC),arp_p_src_protocol_address_start(),arp_p_src_protocol_address_end());  // - - 曾加Sender protocol address
        treeF = DTree::addNext(treeF,arp_msg_hardware_address(arp,SD::DST),arp_p_dst_hardware_address_start(),arp_p_dst_hardware_address_end());  //- - 曾加Target mac address
        treeF = DTree::addNext(treeF,arp_msg_protocol_address(arp,SD::DST),arp_p_dst_protocol_address_start(),arp_p_dst_protocol_address_end());  //- - 曾加Target protocol address
    }else{
        dissect_result_list->back()->srcPort = -1;
        dissect_result_list->back()->dstPort = -1;
        dissect_result_list->back()->protocolStack.append("ARP");
        dissect_result_list->back()->HeadersLen += sizeof (arp_hdr);

        dissect_result_list->back()->Protocol = "ARP";
        dissect_result_list->back()->Info = arp_msg_info(arp);
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  get方法
ushort Dissecter_arp::arp_get_protocol_type(const arp_hdr *header){
    return ntohs(header->protocol_type);
}

QString Dissecter_arp::arp_get_protocol_type_name(const arp_hdr *header){
    switch (arp_get_protocol_type(header)) {
        case (ushort)0x0800:
            return "IPv4";
        default:
            return "ARP承载的协议类型有待添加，协议号为" + QString::asprintf("%02x%02x"
                                                             ,(&header->protocol_type)[0]
                                                             ,(&header->protocol_type)[1]
                    );
    }
}

ushort Dissecter_arp::arp_get_hardware_type(const arp_hdr *header){
    return ntohs(header->hardware_type);
}

QString Dissecter_arp::arp_get_hardware_type_name(const arp_hdr *header){
    return pcap_datalink_val_to_name(ntohs(header->hardware_type));
}

uchar Dissecter_arp::arp_get_hardware_address_size(const arp_hdr *header){
    return header->hardware_address_len;
}

uchar Dissecter_arp::arp_get_protocol_address_size(const arp_hdr *header){
    return header->protocol_address_len;
}

ushort Dissecter_arp::arp_get_opcode(const arp_hdr *header){
    return ntohs(header->op);
}

QString Dissecter_arp::arp_get_opcode_name(const arp_hdr *header){
    switch (arp_get_opcode(header)) {
        case (ushort)1:
            return "Request";
        case (ushort)2:
            return "Reply";
        default:
            return "未知ARP操作类型，值为" + QString(arp_get_opcode(header));
    }
}

QString Dissecter_arp::arp_get_hardware_address(const arp_hdr *header,SD sd){
    if(sd == SD::SRC){
        return QString::asprintf("%02x%02x%02x%02x%02x%02x"
                ,header->src_hardware[0]
                ,header->src_hardware[1]
                ,header->src_hardware[2]
                ,header->src_hardware[3]
                ,header->src_hardware[4]
                ,header->src_hardware[5]
                );
    }else{
        return QString::asprintf("%02x%02x%02x%02x%02x%02x"
                ,header->dst_hardware[0]
                ,header->dst_hardware[1]
                ,header->dst_hardware[2]
                ,header->dst_hardware[3]
                ,header->dst_hardware[4]
                ,header->dst_hardware[5]
                );
    }
}

QString Dissecter_arp::arp_get_protocol_address(const arp_hdr *header,SD sd){
    if(sd == SD::SRC){
        return QString::asprintf("%d.%d.%d.%d"
                ,header->src_protocol[0]
                ,header->src_protocol[1]
                ,header->src_protocol[2]
                ,header->src_protocol[3]
                );
    }else{
        return QString::asprintf("%d.%d.%d.%d"
                ,header->dst_protocol[0]
                ,header->dst_protocol[1]
                ,header->dst_protocol[2]
                ,header->dst_protocol[3]
                );
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  msg方法
QString Dissecter_arp::arp_msg_top_level(const arp_hdr *header){
    return "Address Resolution Protocol (" + arp_get_opcode_name(header) + ")";
}

QString Dissecter_arp::arp_msg_protocol_type(const arp_hdr *header){
    ushort type = arp_get_protocol_type(header);
    return "Protocol type: " + arp_get_protocol_type_name(header)
            + "("
            + QString::asprintf("0x%02x%02x",((uchar*)&type)[1],((uchar*)&type)[0])
            + ")";
}

QString Dissecter_arp::arp_msg_hardware_type(const arp_hdr *header){
    return "Hardware type: " + arp_get_hardware_type_name(header)
            + "("
            + QString::asprintf("%d",arp_get_hardware_type(header))
            + ")";
}

QString Dissecter_arp::arp_msg_hardware_size(const arp_hdr *header){
    return "Hardware address size: " + QString::asprintf("%d",arp_get_hardware_address_size(header));
}

QString Dissecter_arp::arp_msg_protocol_size(const arp_hdr *header){
    return "Protocol address size: " + QString::asprintf("%d",arp_get_protocol_address_size(header));
}

QString Dissecter_arp::arp_msg_op_code(const arp_hdr *header){
    return "Opcode :"
            + QString(arp_get_opcode_name(header))
            + "(" + QString::asprintf("%d",arp_get_opcode(header)) + ")";
}

QString Dissecter_arp::arp_msg_hardware_address(const arp_hdr *header,SD sd){
    QString str;
    if(sd == SD::SRC){
        str = "Sender MAC address:";
    }else{
        str = "Target MAC address:";
    }
    return str + arp_get_hardware_address(header,sd);
}

QString Dissecter_arp::arp_msg_protocol_address(const arp_hdr *header,SD sd){
    QString str;
    if(sd == SD::SRC){
        str = "Sender Protocol address:";
    }else{
        str = "Target Protocol address:";
    }
    return str + arp_get_protocol_address(header,sd);
}

QString Dissecter_arp::arp_msg_info(const arp_hdr *header){
    switch (arp_get_opcode(header)) {
        case (ushort)1:
            return "Who has " + arp_get_protocol_address(header,SD::DST) + "?    "
                    + "Tell " + arp_get_protocol_address(header,SD::SRC);
        case (ushort)2:
            return arp_get_protocol_address(header,SD::SRC) + " is at "
                    + arp_get_hardware_address(header,SD::SRC);
        default:
            return "未知ARP操作类型，值为" + QString(arp_get_opcode(header));
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  p方法
qint32 Dissecter_arp::arp_p_top_level_start(){
     return sizeof(eth_hdr);
}

qint32 Dissecter_arp::arp_p_hardware_type_start(){
    return arp_p_top_level_start();
}

qint32 Dissecter_arp::arp_p_protocol_type_start(){
    return arp_p_hardware_type_start() + ARP_LENS::HARDWARE_TYPE;
}

qint32 Dissecter_arp::arp_p_hardware_address_len_start(){
    return arp_p_protocol_type_start() + ARP_LENS::PROTOCOL_TYPE;
}

qint32 Dissecter_arp::arp_p_protocol_address_len_start(){
    return arp_p_hardware_address_len_start() + ARP_LENS::HARDWARE_ADDRESS_LEN;
}

qint32 Dissecter_arp::arp_p_opcode_start(){
    return arp_p_protocol_address_len_start() + ARP_LENS::PROTOCOL_ADDRESS_LEN;
}

qint32 Dissecter_arp::arp_p_src_hardware_address_start(){
    return arp_p_opcode_start() + ARP_LENS::OPCODE;
}

qint32 Dissecter_arp::arp_p_src_protocol_address_start(){
    return arp_p_src_hardware_address_start() + ARP_LENS::SRC_HARDWARE;
}

qint32 Dissecter_arp::arp_p_dst_hardware_address_start(){
    return arp_p_src_protocol_address_start() + ARP_LENS::SRC_PROTOCOL;
}

qint32 Dissecter_arp::arp_p_dst_protocol_address_start(){
    return arp_p_dst_hardware_address_start() + ARP_LENS::DST_HARDWARE;
}

qint32 Dissecter_arp::arp_p_top_level_end(){
    return arp_p_dst_protocol_address_start() + ARP_LENS::DST_PROTOCOL -1;
}

qint32 Dissecter_arp::arp_p_hardware_type_end(){
    return arp_p_protocol_type_start() - 1;
}

qint32 Dissecter_arp::arp_p_protocol_type_end(){
    return arp_p_hardware_address_len_start() - 1;
}

qint32 Dissecter_arp::arp_p_hardware_address_len_end(){
    return arp_p_protocol_address_len_start() - 1;
}

qint32 Dissecter_arp::arp_p_protocol_address_len_end(){
    return arp_p_opcode_start() - 1;
}

qint32 Dissecter_arp::arp_p_opcode_end(){
    return arp_p_src_hardware_address_start() - 1;
}

qint32 Dissecter_arp::arp_p_src_hardware_address_end(){
    return arp_p_src_protocol_address_start() - 1;
}

qint32 Dissecter_arp::arp_p_src_protocol_address_end(){
    return arp_p_dst_hardware_address_start() - 1;
}

qint32 Dissecter_arp::arp_p_dst_hardware_address_end(){
    return arp_p_dst_protocol_address_start() - 1;
}

qint32 Dissecter_arp::arp_p_dst_protocol_address_end(){
    return arp_p_top_level_end();
}

