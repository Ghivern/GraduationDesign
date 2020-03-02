#include "dissecter_frame.h"

timeval Dissecter_frame::tv;

tree_node_t* Dissecter_frame::dissect(const pcap_pkthdr *pkthdr
                                      ,dissect_result_list_t *dissect_result_list
                                      ,info_for_detailed_dissect_t *info){

    tree_node_t *tree = NULL;
    if( info != NULL){        //详细解析  >> 处理协议树   >>   添加Frame顶层
        tree = DTree::newNode(frame_msg_top_level(pkthdr,info),frame_p_top_level_start(),frame_p_top_level_end(dissect_result_list,info)); //-   添加Frame顶层
        tree_node_t * nextF = DTree::addNextFloor(tree,frame_msg_interface_id(info)); // - - 添加interface id
        DTree::addNextFloor(tree->nextFloor,frame_msg_interface_name(info));  // - - -   添加interface name
        nextF = DTree::addNext(nextF,frame_msg_encapsulation_type(info)); // - -  添加封装类型
        nextF = DTree::addNext(nextF,frame_msg_arrive_time(pkthdr));  // - -  添加到达时间
        nextF = DTree::addNext(nextF,frame_msg_time_shift_for_this_packet());  // - -  添加 Time shift for this packet
        nextF = DTree::addNext(nextF,frame_msg_epoch_time(pkthdr));  // - -  添加Epoch Time
        nextF = DTree::addNext(nextF,frame_msg_time_delta_from_previous_captured_frame(dissect_result_list,info));  // - -  添加Time delta from previous captured frame
        nextF = DTree::addNext(nextF,frame_msg_time_delta_from_previous_displayed_fram(dissect_result_list,info));  // - -  添加Time delta from previous displayed frame
        nextF = DTree::addNext(nextF,frame_msg_time_since_reference_or_first_frame(dissect_result_list,info));  // - -  添加Time since reference or first frame
        nextF = DTree::addNext(nextF,frame_msg_frame_number(info));  // - - 添加Frame Number
        nextF = DTree::addNext(nextF,frame_msg_frame_length(pkthdr));  // - - 添加Frame Length
        nextF = DTree::addNext(nextF,frame_msg_capture_length(pkthdr));  // - - 添加Capture Length
        nextF = DTree::addNext(nextF,frame_msg_protocol_stack(dissect_result_list,info));      // - -添加Protocols 栈
    }
    else // 简单解析 NO,Time,Length(Frame)     ,Src,Dst,(IP/MAC)     Protocol,Info(顶层协议)  protocolStack,headersLen(每曾均处理)
    {
        // NO Time Length
        dissect_result_t *dissect_result = new dissect_result_t;
        dissect_result->HeadersLen = 0;
        dissect_result->protocolStack.append("eth");
        dissect_result->Length = pkthdr->caplen;   //添加Length
        dissect_result->TimeSinceFirstFrame = frame_get_since_reference_or_first_frame(pkthdr,dissect_result_list);  //添加Time since first frame
        dissect_result->No = dissect_result_list->length();  //添加No
        dissect_result_list->append(dissect_result);      //将指向简单解析结果的指针存入列表
    }
    return tree;
}



//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   get方法
QString Dissecter_frame::frame_get_str_time(const pcap_pkthdr *pkthdr){
    time_t time_sec = pkthdr->ts.tv_sec;
    struct tm *local;
    local = localtime(&time_sec);
    char strTime[128];
    strftime(strTime,64, "%Y-%m-%d %H:%M:%S", local);
    return QString::asprintf("%s.%ld",strTime,pkthdr->ts.tv_usec);
}

float Dissecter_frame::frame_get_since_reference_or_first_frame(const pcap_pkthdr *pkthdr,dissect_result_list_t *list){
    if(list->length() == 0){
        Dissecter_frame::tv.tv_sec = pkthdr->ts.tv_sec;
        Dissecter_frame::tv.tv_usec = pkthdr->ts.tv_usec;
        return  0.0;
    }else{
        return (pkthdr->ts.tv_sec - Dissecter_frame::tv.tv_sec)
                + (pkthdr->ts.tv_usec - Dissecter_frame::tv.tv_usec)/1000000.0;
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  msg方法
QString Dissecter_frame::frame_msg_top_level(const pcap_pkthdr *pkthdr, info_for_detailed_dissect_t *info){
    return QString::asprintf("Frame %lld : %d bytes (%d bits) on ",info->No,pkthdr->len,pkthdr->len * 8)
    + info->devName
    + QString::asprintf(" , %d bytes (%d bits) Captured on interface %d",pkthdr->caplen,pkthdr->caplen*8,info->devIndex);
}

QString Dissecter_frame::frame_msg_interface_id(info_for_detailed_dissect_t *info){
    return QString::asprintf("Interface id : %d",info->devIndex);
}

QString Dissecter_frame::frame_msg_interface_name(info_for_detailed_dissect_t *info){
    return QString::asprintf("Interface name : ") + info->devName;
}

QString Dissecter_frame::frame_msg_encapsulation_type(info_for_detailed_dissect_t *info){
    return QString::asprintf("Encapsulation type :") + info->dataLinkName;
}

QString Dissecter_frame::frame_msg_arrive_time(const pcap_pkthdr *pkthdr){
    return QString::asprintf("Arrival Time : ")+ frame_get_str_time(pkthdr);
}

QString Dissecter_frame::frame_msg_time_shift_for_this_packet(){
    return QString::asprintf("[Time shift for this packet: 0.000000000 seconds]");
}

QString Dissecter_frame::frame_msg_epoch_time(const pcap_pkthdr *pkthdr){
    return QString::asprintf("Epoch Time: %lld.%lld seconds",(qint64)pkthdr->ts.tv_sec,(qint64)pkthdr->ts.tv_usec);

}

QString Dissecter_frame::frame_msg_time_delta_from_previous_captured_frame(dissect_result_list_t *list,info_for_detailed_dissect_t *info){
    return QString::asprintf("[ Time delta from previous captured frame : %f ]"
                              ,list->at(info->No)->TimeSinceFirstFrame
                                - list->at(info->No == 0 ? info->No : (info->No - 1))->TimeSinceFirstFrame);
}

QString Dissecter_frame::frame_msg_time_delta_from_previous_displayed_fram(dissect_result_list_t *list,info_for_detailed_dissect_t *info){
    return QString::asprintf("[ Time delta from previous displayed frame : %f ]"
                              ,(list->at(info->No)->DisplayTime.tv_sec
                              - list->at(info->No == 0 ? info->No : (info->No - 1))->DisplayTime.tv_sec)
                              +
                              (list->at(info->No)->DisplayTime.tv_usec
                               - list->at(info->No == 0 ? info->No : (info->No - 1))->DisplayTime.tv_usec)/1000000.0
                              );

}

QString Dissecter_frame::frame_msg_time_since_reference_or_first_frame(dissect_result_list_t *list,info_for_detailed_dissect_t *info){
    return QString::asprintf("Time since reference or first frame: %f seconds",list->at(info->No)->TimeSinceFirstFrame);
}

QString Dissecter_frame::frame_msg_frame_number(info_for_detailed_dissect_t *info){
    return QString::asprintf("Frame Number:%lld",info->No);

}

QString Dissecter_frame::frame_msg_frame_length(const pcap_pkthdr *pkthdr){
    return QString::asprintf("Frame Length:%d bytes (%d bits)",pkthdr->len,pkthdr->len * 8);
}

QString Dissecter_frame::frame_msg_capture_length(const pcap_pkthdr *pkthdr){
    return QString::asprintf("Capture Length:%d bytes (%d bits)",pkthdr->caplen,pkthdr->caplen * 8);
}

QString Dissecter_frame::frame_msg_protocol_stack(dissect_result_list_t *list, info_for_detailed_dissect_t *info){
    dissect_result_t *res = list->at(info->No);
    QString protocolStack = "[ Protocols in frame: ";
    for(qint32 index = 0; index < res->protocolStack.length(); index++){
        if(index == res->protocolStack.length() - 1)
            protocolStack.append(res->protocolStack.at(index) + " ]");
        else
            protocolStack.append(res->protocolStack.at(index) + ":");
        }
    return protocolStack;
}
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ p方法
qint32 Dissecter_frame::frame_p_top_level_start(){
    return 0;
}

qint32 Dissecter_frame::frame_p_top_level_end(dissect_result_list_t *list, info_for_detailed_dissect_t *info){
    return list->at(info->No)->HeadersLen - 1;
}
