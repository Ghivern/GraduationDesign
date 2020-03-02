#ifndef DISSECTER_H
#define DISSECTER_H

#include <QObject>
#include "../global.h"
#include "global/global_dissect.h"

class Dissecter:public QObject
{
    Q_OBJECT
public:
    Dissecter();

    //所有解析器具均重写此两种方法，使用多态

    //简单解析
    virtual tree_node_t *dissect(const u_char *packet,const pcap_pkthdr *pkthdr
                                 ,dissect_result_list_t *dissect_result_list,info_for_detailed_dissect_t *info = NULL);



};

#endif // DISSECTER_H
