#ifndef DTREE_H
#define DTREE_H

#include "../global.h"

class DTree
{
public:
    DTree();

    //操作协议书节点
    static tree_node_t* newNode(QString msg,qint32 start = -1,qint32 end = -1);
    static tree_node_t* addNext(tree_node_t *node,QString msg ,qint32 start = -1,qint32 end = -1);
    static tree_node_t* addNextFloor(tree_node_t *node,QString msg,qint32 start = -1,qint32 end = -1);

    static void fillOneNode(tree_node_t *node,QString msg);
};

#endif // DTREE_H
