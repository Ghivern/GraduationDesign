#ifndef DISSECTER_IP_H
#define DISSECTER_IP_H

#include "../dissecter.h"

#include "dissecter_tcp.h"
#include "dissecter_udp.h"



class Dissecter_ip
{

public:
    static void dissect_ip(const ip_hdr *ip//const u_char *packet
                           ,dissect_result_list_t *dissect_result_list
                           ,tree_node_t *tree = NULL
                           ,info_for_detailed_dissect_t *info = NULL);
    static void SetValitation(bool v);
    static bool GetValitation();

private:
    static bool ip_valitation;

    static tcp_hdr* ip_get_tcp_header(const ip_hdr *ip);
    static udp_hdr* ip_get_udp_header(const ip_hdr *ip);

    static QString ip_get_address(const ip_hdr *header,SD sd);
    static uchar ip_get_type(const ip_hdr *header);
    static QString ip_get_type_name(const ip_hdr *header);
    static uchar ip_get_version(const ip_hdr *header);
    static uchar ip_get_header_length(const ip_hdr *header);
    static uchar ip_get_DS(const ip_hdr *header);
    static uchar ip_get_DSCP(const ip_hdr *header);
    static uchar ip_get_ECN(const ip_hdr *header);
    static ushort ip_get_total_length(const ip_hdr *header);
    static ushort ip_get_identification(const ip_hdr *header);
    static ushort ip_get_flags_and_offset(const ip_hdr *header);
    static uchar ip_get_flags_reserved_bit(const ip_hdr *header);
    static uchar ip_get_flags_MF(const ip_hdr *header);
    static uchar ip_get_flags_DF(const ip_hdr *header);
    static ushort ip_get_offset(const ip_hdr *header);
    static uchar ip_get_ttl(const ip_hdr *header);
    static ushort ip_get_header_checksum(const ip_hdr *header);

    static QString ip_msg_top_level(const ip_hdr *header);
    static QString ip_msg_version(const ip_hdr *header);
    static QString ip_msg_header_length(const ip_hdr *header);
    static QString ip_msg_DS(const ip_hdr *header);
    static QString ip_msg_DSCP(const ip_hdr *header);
    static QString ip_msg_ECN(const ip_hdr *header);
    static QString ip_msg_total_length(const ip_hdr *header);
    static QString ip_msg_identification(const ip_hdr *header);
    static QString ip_msg_flags_and_offset(const ip_hdr *header);
    static QString ip_msg_reserved_bit(const ip_hdr *header);
    static QString ip_msg_MF(const ip_hdr *header);
    static QString ip_msg_DF(const ip_hdr *header);
    static QString ip_msg_offset(const ip_hdr *header);
    static QString ip_msg_ttl(const ip_hdr *header);
    static QString ip_msg_protocol(const ip_hdr *header);
    static QString ip_msg_header_checksum(const ip_hdr *header);
    static QString ip_msg_header_checksum_status(const ip_hdr *header);
    static QString ip_msg_address(const ip_hdr *header,SD sd);

    static qint32 ip_p_top_level_start();
    static qint32 ip_p_version_and_header_len_start();
    static qint32 ip_p_tos_start();
    static qint32 ip_p_total_len_start();
    static qint32 ip_p_ident_start();
    static qint32 ip_p_flags_and_offset_start();
    static qint32 ip_p_ttl_start();
    static qint32 ip_p_protocol_start();
    static qint32 ip_p_checksum_start();
    static qint32 ip_p_source_start();
    static qint32 ip_p_destination_start();
    static qint32 ip_p_top_level_end();
    static qint32 ip_p_version_and_header_len_end();
    static qint32 ip_p_tos_end();
    static qint32 ip_p_total_len_end();
    static qint32 ip_p_ident_end();
    static qint32 ip_p_flags_and_offset_end();
    static qint32 ip_p_ttl_end();
    static qint32 ip_p_protocol_end();
    static qint32 ip_p_checksum_end();
    static qint32 ip_p_source_end();
    static qint32 ip_p_destination_end();
};
#endif // DISSECTER_IP_H
