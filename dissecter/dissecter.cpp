#include "dissecter.h"

Dissecter::Dissecter()
{

}

tree_node_t *Dissecter::dissect(const u_char *packet, const pcap_pkthdr *pkthdr, dissect_result_list_t *dissect_result_list, info_for_detailed_dissect_t *info){
    Q_UNUSED(packet)
    Q_UNUSED(pkthdr)
    Q_UNUSED(dissect_result_list)
    Q_UNUSED(info)
    return NULL;
}
