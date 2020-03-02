#ifndef DISSECTER_ARP_H
#define DISSECTER_ARP_H

#include "../dissecter.h"

class Dissecter_arp
{

public:
    static void dissect_arp(const arp_hdr *arp//const u_char *packet
                    ,dissect_result_list_t *dissect_result_list
                    ,tree_node_t *tree = NULL
                    ,info_for_detailed_dissect_t *info = NULL);

private:
    //----Start----Start----Start----Start----Start----Start----Start
    //ARP
    static ushort arp_get_protocol_type(const arp_hdr *header);
    static QString arp_get_protocol_type_name(const arp_hdr *header);
    static ushort arp_get_hardware_type(const arp_hdr *header);
    static QString arp_get_hardware_type_name(const arp_hdr *header);
    static uchar arp_get_hardware_address_size(const arp_hdr *header);
    static uchar arp_get_protocol_address_size(const arp_hdr *header);
    static ushort arp_get_opcode(const arp_hdr *header);
    static QString arp_get_opcode_name(const arp_hdr *header);
    static QString arp_get_hardware_address(const arp_hdr *header,SD sd);
    static QString arp_get_protocol_address(const arp_hdr *header,SD sd);

    static QString arp_msg_top_level(const arp_hdr *header);
    static QString arp_msg_protocol_type(const arp_hdr *header);
    static QString arp_msg_hardware_type(const arp_hdr *header);
    static QString arp_msg_hardware_size(const arp_hdr *header);
    static QString arp_msg_protocol_size(const arp_hdr *header);
    static QString arp_msg_op_code(const arp_hdr *header);
    static QString arp_msg_hardware_address(const arp_hdr *header,SD sd);
    static QString arp_msg_protocol_address(const arp_hdr *header,SD sd);
    static QString arp_msg_info(const arp_hdr *header);

    static qint32 arp_p_top_level_start();
    static qint32 arp_p_hardware_type_start();
    static qint32 arp_p_protocol_type_start();
    static qint32 arp_p_hardware_address_len_start();
    static qint32 arp_p_protocol_address_len_start();
    static qint32 arp_p_opcode_start();
    static qint32 arp_p_src_hardware_address_start();
    static qint32 arp_p_dst_hardware_address_start();
    static qint32 arp_p_src_protocol_address_start();
    static qint32 arp_p_dst_protocol_address_start();
    static qint32 arp_p_top_level_end();
    static qint32 arp_p_hardware_type_end();
    static qint32 arp_p_protocol_type_end();
    static qint32 arp_p_hardware_address_len_end();
    static qint32 arp_p_protocol_address_len_end();
    static qint32 arp_p_opcode_end();
    static qint32 arp_p_src_hardware_address_end();
    static qint32 arp_p_dst_hardware_address_end();
    static qint32 arp_p_src_protocol_address_end();
    static qint32 arp_p_dst_protocol_address_end();
    //----End----End----End----End----End----End----End----End----End
};

#endif // DISSECTER_ARP_H
