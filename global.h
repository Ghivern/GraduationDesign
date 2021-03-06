#ifndef GLOBAL_H
#define GLOBAL_H
#include <QtCore>
#include <QList>
#include <QDebug>

#include "pcap.h"

typedef QList<pcap_if_t *> device_list_t;  //定义存储设备的列表类型

typedef  QList<const u_char*> raw_packet_list_t;  //定义存储原始数据包的列表类型
typedef  QList<const pcap_pkthdr*> packet_pkthdr_list_t; //定义存储数据包pkthdr的列表类型

typedef QList<QString> protocols_t;
typedef struct dissect_result_t{  //包简单解析结果
  qint64 No;  // index of packet in raw packet list and pkthdr list ,ui No is based on this field
  QString Source;  // ip source address
  QString Destination;  // ip destination address
  QString MacSource;  //  mac source address
  QString MacDestination; // mac destination 
  qint16 Length;  // packet caplen
  QString Protocol; // top level protocol name
  QString Info; //  a small message for displaying on ui
  timeval DisplayTime;  //record display time , this field is filled after dissect result displayed on ui
  float TimeSinceFirstFrame; // time since first frame
  qint32 HeadersLen; // protocol headers len (without payload data)
  protocols_t protocolStack; //record protocol stack
  qint32 srcPort = -1; //record source port
  qint32 dstPort = -1; // record destination port 
}dissect_result_t;  //source,destination,protocol,info由上层协议添加
typedef QList<dissect_result_t*> dissect_result_list_t;  //定义存储简单解析结果的列表类型

//协议树节点
typedef struct tree_node_t{
    tree_node_t *next;
    tree_node_t *nextFloor;
    QString msg;
    qint32 start;
    qint32 end;
}tree_node_t;


//详细解析时需要的信息

//typedef QHash<QString,tree_node_t*> nodes_wait_for_deal_t;
typedef struct info_for_detailed_dissect_t{
    qint64 No;
    QString devName;
    qint32 devIndex;
    QString dataLinkName;
    qint32 dataLinkVal;
}info_for_detailed_dissect_t;

#endif // GLOBAL_H
