#ifndef DISSECTER_TCP_H
#define DISSECTER_TCP_H

#include "../dissecter.h"

class Dissecter_tcp
{
public:
    static void dissect_tcp(const tcp_hdr *tcp//const u_char *packet
                            ,dissect_result_list_t *dissect_result_list
                            ,tree_node_t *tree = NULL
                            ,info_for_detailed_dissect_t *info = NULL);
private:
    static QHash<QString,qint64> streamIndex;


    static ushort tcp_get_src_port(const tcp_hdr *header);
    static ushort tcp_get_dst_port(const tcp_hdr *header);
    static uint tcp_get_seq(const tcp_hdr *header);
    static uint tcp_get_ack(const tcp_hdr *header);
    static uchar tcp_get_header_len(const tcp_hdr *header);
    static ushort tcp_get_payload_len(const tcp_hdr *header,qint16 caplen);
    static uchar tcp_get_URG(const tcp_hdr *header);
    static uchar tcp_get_ACK(const tcp_hdr *header);
    static uchar tcp_get_PSH(const tcp_hdr *header);
    static uchar tcp_get_RST(const tcp_hdr *header);
    static uchar tcp_get_SYN(const tcp_hdr *header);
    static uchar tcp_get_FIN(const tcp_hdr *header);
};

#endif  //DISSECTER_TCP_H
