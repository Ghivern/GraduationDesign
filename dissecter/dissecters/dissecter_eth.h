#ifndef DISSECTER_ETH_H
#define DISSECTER_ETH_H

#include "../dissecter.h"

#include "dissecter_frame.h"
#include "dissecter_ip.h"
#include "dissecter_arp.h"

class Dissecter_eth:public Dissecter
{
public:
    Dissecter_eth();
    tree_node_t *dissect(const u_char *packet
                         ,const pcap_pkthdr *pkthdr
                         ,dissect_result_list_t *dissect_result_list
                         ,info_for_detailed_dissect_t *info = NULL) Q_DECL_OVERRIDE;
private:
    //需要增加记录流的计数器，和各个流的统计情况

    eth_hdr *ether_get_eth_header(const uchar *packet);
    arp_hdr *ether_get_arp_header(const eth_hdr* eth);
    ip_hdr *ether_get_ip_header(const eth_hdr* eth);

    QString ether_get_src(eth_hdr *header);
    QString ether_get_dst(eth_hdr *header);
    uchar ether_get_src_byte(eth_hdr *header,uchar index);
    uchar ether_get_dst_byte(eth_hdr *header,uchar index);
    uchar ether_get_src_first_byte(eth_hdr *header);
    uchar ether_get_dst_first_byte(eth_hdr *header);
    ushort ether_get_type(eth_hdr *header);
    QString ether_get_type_name(eth_hdr *header);
    QString ether_get_LG(uchar firstByte);
    QString ether_get_IG(uchar firstByte);

    QString ether_msg_top_level(eth_hdr *header,info_for_detailed_dissect_t *info);
    QString ether_msg_address(eth_hdr *header,SD srcOrDst,QString preambles);
    QString ether_msg_LG(SD secOrDst,eth_hdr *header);
    QString ether_msg_IG(SD secOrDst,eth_hdr *header);
    QString ether_msg_type(eth_hdr *header);

    qint32 ether_p_top_level_start();
    qint32 ether_p_dst_address_start();
    qint32 ether_p_src_address_start();
    qint32 ether_p_type_start();
    qint32 ether_p_dst_LG_IG_start();
    qint32 ether_p_src_LG_IG_start();
    qint32 ether_p_top_level_end();
    qint32 ether_p_dst_address_end();
    qint32 ether_p_src_address_end();
    qint32 ether_p_type_end();
    qint32 ether_p_dst_LG_IG_end();
    qint32 ether_p_src_LG_IG_end();
};

#endif // DISSECTER_ETH_H
