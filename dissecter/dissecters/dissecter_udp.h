#ifndef DISSECTER_UDP_H
#define DISSECTER_UDP_H

#include "../dissecter.h"

class Dissecter_udp
{
public:
    static void dissect_udp(const udp_hdr *udp//const u_char *packet
                            ,dissect_result_list_t *dissect_result_list
                            ,tree_node_t *tree = NULL
                            ,info_for_detailed_dissect_t *info = NULL);
    static void SetValitation(bool v);
    static bool GetValitation();
private:
    static bool udp_valitation;
    static QHash<QString,qint64> streamIndex;

    static ushort udp_get_src_port(const udp_hdr *header);
    static ushort udp_get_dst_port(const udp_hdr *header);
    static ushort udp_get_length(const udp_hdr *header);
    static ushort udp_get_check_sum(const udp_hdr *header);

    static QString udp_msg_top_level(const udp_hdr *header);
    static QString udp_msg_src_port(const udp_hdr *header);
    static QString udp_msg_dst_port(const udp_hdr *header);
    static QString udp_msg_length(const udp_hdr *header);
    static QString udp_msg_check_sum(const udp_hdr *header);
    static QString udp_msg_check_sum_status(const udp_hdr *header);

    static qint32 udp_p_top_level_start();
    static qint32 udp_p_src_port_start();
    static qint32 udp_p_dst_port_start();
    static qint32 udp_p_length_start();
    static qint32 udp_p_check_sum_start();
    static qint32 udp_p_top_level_end();
    static qint32 udp_p_src_port_end();
    static qint32 udp_p_dst_port_end();
    static qint32 udp_p_length_end();
    static qint32 udp_p_check_sum_end();
};

#endif // DISSECTER_UDP_H
