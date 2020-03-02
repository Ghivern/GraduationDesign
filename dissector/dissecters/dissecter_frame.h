#ifndef DISSECTER_FRAME_H
#define DISSECTER_FRAME_H

#include "../dissecter.h"

class Dissecter_frame
{
public:
    static tree_node_t *dissect(const pcap_pkthdr *pkthdr
                                ,dissect_result_list_t *dissect_result_list
                                ,info_for_detailed_dissect_t *info = NULL);
private:
    static timeval tv;  //记录第一个包的获取时间

    static QString frame_get_str_time(const pcap_pkthdr *pkthdr);
    static float frame_get_since_reference_or_first_frame(const pcap_pkthdr *pkthdr,dissect_result_list_t *list);

    static QString frame_msg_top_level(const pcap_pkthdr *pkthdr,info_for_detailed_dissect_t *info);
    static QString frame_msg_interface_id(info_for_detailed_dissect_t* info);
    static QString frame_msg_interface_name(info_for_detailed_dissect_t *info);
    static QString frame_msg_encapsulation_type(info_for_detailed_dissect_t *info);
    static QString frame_msg_arrive_time(const pcap_pkthdr *pkthdr);
    static QString frame_msg_time_shift_for_this_packet();
    static QString frame_msg_epoch_time(const pcap_pkthdr *pkthdr);
    static QString frame_msg_time_delta_from_previous_captured_frame(dissect_result_list_t *list,info_for_detailed_dissect_t *info);
    static QString frame_msg_time_delta_from_previous_displayed_fram(dissect_result_list_t *list,info_for_detailed_dissect_t *info);
    static QString frame_msg_time_since_reference_or_first_frame(dissect_result_list_t *list,info_for_detailed_dissect_t *info);
    static QString frame_msg_frame_number(info_for_detailed_dissect_t *info);
    static QString frame_msg_frame_length(const pcap_pkthdr *pkthdr);
    static QString frame_msg_capture_length(const pcap_pkthdr *pkthdr);
    static QString frame_msg_protocol_stack(dissect_result_list_t *list,info_for_detailed_dissect_t *info);

    static qint32 frame_p_top_level_start();
    static qint32 frame_p_top_level_end(dissect_result_list_t *list,info_for_detailed_dissect_t *info);
};
#endif // DISSECTER_FRAME_H
