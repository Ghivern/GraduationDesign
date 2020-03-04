#include "dissecter_eth.h"



Dissecter_eth::Dissecter_eth(){}

tree_node_t* Dissecter_eth::dissect(const u_char *packet, const pcap_pkthdr *pkthdr, dissect_result_list_t *dissect_result_list, info_for_detailed_dissect_t *info){
    tree_node_t *treeheader = Dissecter_frame::dissect(pkthdr,dissect_result_list,info);
    tree_node_t *tree = treeheader;
    eth_hdr *ethernet = this->ether_get_eth_header(packet);
    if(info != NULL){   //详细解析  >> 处理协议树  >> 增加链路层
        // 参数描述    父节点，msg,start,end
        tree =  DTree::addNext(tree,this->ether_msg_top_level(ethernet,info),this->ether_p_top_level_start(),this->ether_p_top_level_end()); //-   添加Mac顶层
        tree_node_t *nextF = DTree::addNextFloor(tree,this->ether_msg_address(ethernet,SD::DST,"Destination :"),this->ether_p_dst_address_start(),this->ether_p_dst_address_end());  //- -   添加Destination
        tree_node_t *nextFF = DTree::addNextFloor(nextF,this->ether_msg_address(ethernet,SD::DST,"Address :"),this->ether_p_dst_address_start(),this->ether_p_dst_address_end());  //- - -  添加Address
        nextFF = DTree::addNext(nextFF,this->ether_msg_LG(SD::DST,ethernet),this->ether_p_dst_LG_IG_start(),this->ether_p_dst_LG_IG_end());  //- - -  添加 dst Global/Local标志位
        nextFF = DTree::addNext(nextFF,this->ether_msg_IG(SD::DST,ethernet),this->ether_p_dst_LG_IG_start(),this->ether_p_dst_LG_IG_end());  //- - -  添加 dst Individual/Group标志位
        nextF = DTree::addNext(nextF,this->ether_msg_address(ethernet,SD::SRC,"Source :"),this->ether_p_src_address_start(),this->ether_p_src_address_end());  //- -  添加Source
        nextFF = DTree::addNextFloor(nextF,this->ether_msg_address(ethernet,SD::DST,"Address :"),this->ether_p_src_address_start(),this->ether_p_src_address_end());  //- - - 添加Address
        nextFF = DTree::addNext(nextFF,this->ether_msg_LG(SD::SRC,ethernet),this->ether_p_src_LG_IG_start(),this->ether_p_src_LG_IG_end());  //- - - 添加 src Global/Local标志位
        nextFF = DTree::addNext(nextFF,this->ether_msg_IG(SD::SRC,ethernet),this->ether_p_src_LG_IG_start(),this->ether_p_src_LG_IG_end());  //- - - 添加 src Individual/Group标志位
        nextF = DTree::addNext(nextF,this->ether_msg_type(ethernet),this->ether_p_type_start(),this->ether_p_type_end());  //- - - 添加 Type
    }else{// 简单解析    NO,Time,Length(Frame)     ,Src,Dst,(IP/MAC)     Protocol,Info(顶层协议)  protocolStack,headersLen(每曾均处理)
        dissect_result_list->back()->HeadersLen += sizeof (eth_hdr);
        dissect_result_list->back()->protocolStack.append("ethertype");
        dissect_result_list->back()->Source = this->ether_msg_address(ethernet,SD::SRC,"");
        dissect_result_list->back()->Destination = this->ether_msg_address(ethernet,SD::DST,"");
        dissect_result_list->back()->MacSource = this->ether_msg_address(ethernet,SD::SRC,"");
	dissect_result_list->back()->MacDestination = this->ether_msg_address(ethernet,SD::DST,"");
    }

    //进入下层协议
    switch (this->ether_get_type(ethernet)) {
        case (ushort)0x0800:   //IP
            Dissecter_ip::dissect_ip(this->ether_get_ip_header(ethernet),dissect_result_list,tree,info);
            break;
        case (ushort)0x0806 :  //ARP
            {
                dissect_result_list->back()->Source.append(this->ether_msg_address(ethernet,SD::SRC,""));
                dissect_result_list->back()->Destination.append(this->ether_msg_address(ethernet,SD::DST,""));
                Dissecter_arp::dissect_arp(this->ether_get_arp_header(ethernet),dissect_result_list,tree,info);
            }
            break;
         default:  //IPv6 ...
            {
                dissect_result_list->back()->Source.append(this->ether_msg_address(ethernet,SD::SRC,""));
                dissect_result_list->back()->Destination.append(this->ether_msg_address(ethernet,SD::DST,""));
                ushort ethtype = this->ether_get_type(ethernet);
                dissect_result_list->back()->Protocol.append(this->ether_get_type_name(ethernet));
                dissect_result_list->back()->Info.append(QString::asprintf("有待添加解析器，协议号为0x%02x%02x",(&ethtype)[1],(&ethtype)[0]));
             }
            break;
    }
    return treeheader;
}



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   get方法
eth_hdr* Dissecter_eth::ether_get_eth_header(const uchar *packet){
    return (eth_hdr*)packet;
}

arp_hdr* Dissecter_eth::ether_get_arp_header(const eth_hdr* eth){
    return (arp_hdr*)((uchar*)eth + sizeof (eth_hdr));
}

ip_hdr* Dissecter_eth::ether_get_ip_header(const eth_hdr *eth){
    return (ip_hdr*)((uchar*)eth + sizeof (eth_hdr));
}






QString Dissecter_eth::ether_get_src(eth_hdr *header){
    return QString::asprintf("%02x%02x%02x%02x%02x%02x"
                                            ,header->src_mac[0]
                                            ,header->src_mac[1]
                                            ,header->src_mac[2]
                                            ,header->src_mac[3]
                                            ,header->src_mac[4]
                                            ,header->src_mac[5]
                                            );
}

QString Dissecter_eth::ether_get_dst(eth_hdr *header){
    return QString::asprintf("%02x%02x%02x%02x%02x%02x"
                                            ,header->dst_mac[0]
                                            ,header->dst_mac[1]
                                            ,header->dst_mac[2]
                                            ,header->dst_mac[3]
                                            ,header->dst_mac[4]
                                            ,header->dst_mac[5]
                                            );
}

uchar Dissecter_eth::ether_get_dst_byte(eth_hdr *header, uchar index){
    return header->dst_mac[index];
}

uchar Dissecter_eth::ether_get_src_byte(eth_hdr *header, uchar index){
    return header->src_mac[index];
}

uchar Dissecter_eth::ether_get_dst_first_byte(eth_hdr *header){
    return header->dst_mac[0];
}

uchar Dissecter_eth::ether_get_src_first_byte(eth_hdr *header){
    return header->src_mac[0];
}

QString Dissecter_eth::ether_get_type_name(eth_hdr *header){
    switch (ntohs(header->eth_type)) {
        case (ushort)0x0800:
            return "IPv4";
        case (ushort)0x0806:
            return "ARP";
        default:
            return "Ethernet携带的是其他类型协议数据包";
    }
}

ushort Dissecter_eth::ether_get_type(eth_hdr *header){
    return htons(header->eth_type);
}

QString Dissecter_eth::ether_get_IG(uchar firstByte){
    uchar ig = (firstByte & 0x02) >> 1;
    return
        QString::asprintf(".... ...%d ....  .... = IG bit: ",ig )
        +
        (
                (ig==0) ? QString::asprintf("Individual address ( unicast )")
                           : QString::asprintf("Group address ( multicast/broadcast )")
        );
}

QString Dissecter_eth::ether_get_LG(uchar firstByte){
    uchar lg = firstByte & 0x01;
    return
            QString::asprintf(".... ..%d. ....  .... = LG bit: ",lg)
            +
            (
                (lg == 0) ? QString::asprintf("Global unique address ( factory default )")
                                    : QString::asprintf("Locally administered address ( this is NOT the factory default )")
            );
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   msg方法

QString Dissecter_eth::ether_msg_top_level(eth_hdr *header,info_for_detailed_dissect_t *info){
    return QString(
                    info->dataLinkName
                    + QString::asprintf(" , Src: ") + this->ether_get_src(header)
                    + QString::asprintf(" , Dst: ") + this->ether_get_dst(header)
                    );
}

QString Dissecter_eth::ether_msg_address(eth_hdr *header,SD srcOrDst, QString preambles){
    if(srcOrDst == SD::SRC){
        return QString(
                    preambles
                    + this->ether_get_src(header)
                    );
    }else{
        return QString(
                    preambles
                    + this->ether_get_dst(header)
                    );
    }
}

QString Dissecter_eth::ether_msg_IG(SD secOrDst, eth_hdr *header){
    if(secOrDst == SD::DST){
        return QString( this->ether_get_IG( this->ether_get_dst_first_byte(header) ) );
    }else{
        return QString( this->ether_get_IG( this->ether_get_src_first_byte(header) ) );
    }
}

QString Dissecter_eth::ether_msg_LG(SD secOrDst, eth_hdr *header){
    if(secOrDst == SD::DST){
        return QString( this->ether_get_LG( this->ether_get_dst_first_byte(header) ) );
    }else{
        return QString( this->ether_get_LG( this->ether_get_src_first_byte(header) ) );
    }
}

QString Dissecter_eth::ether_msg_type(eth_hdr *header){
    ushort type = this->ether_get_type(header);
    return QString(
                     QString::asprintf("Type : ")
                     + this->ether_get_type_name(header)
                     + QString::asprintf(" ( 0x%02x %02x )",((u_char*)&(type))[1],((u_char*)&(type))[0])
                );
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   p方法
qint32 Dissecter_eth::ether_p_top_level_start(){
    return 0;
}

qint32 Dissecter_eth::ether_p_dst_address_start(){
    return this->ether_p_top_level_start();
}

qint32 Dissecter_eth::ether_p_src_address_start(){
    return this->ether_p_dst_address_start() + ETH_LENS::DSTMAC;
}

qint32 Dissecter_eth::ether_p_type_start(){
    return this->ether_p_src_address_start() + ETH_LENS::SRCMAC;
}

qint32 Dissecter_eth::ether_p_dst_LG_IG_start(){
    return this->ether_p_dst_address_start();
}

qint32 Dissecter_eth::ether_p_src_LG_IG_start(){
    return this->ether_p_src_address_start();
}

qint32 Dissecter_eth::ether_p_top_level_end(){
    return this->ether_p_type_start() + ETH_LENS::ETHTYPE - 1;
}

qint32 Dissecter_eth::ether_p_dst_address_end(){
    return this->ether_p_src_address_start() - 1;
}

qint32 Dissecter_eth::ether_p_src_address_end(){
    return this->ether_p_type_start() - 1;
}

qint32 Dissecter_eth::ether_p_type_end(){
    return this->ether_p_top_level_end();
}

qint32 Dissecter_eth::ether_p_dst_LG_IG_end(){
    return this->ether_p_dst_LG_IG_start() + ETH_LENS::LGIG - 1;
}

qint32 Dissecter_eth::ether_p_src_LG_IG_end(){
    return this->ether_p_src_LG_IG_start() + ETH_LENS::LGIG - 1;
}
