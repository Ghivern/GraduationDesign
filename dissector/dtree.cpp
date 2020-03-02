#include "dtree.h"

DTree::DTree()
{

}

//static methods 处理协议树节点
tree_node_t* DTree::newNode(QString msg,qint32 start,qint32 end){
    //tree_node_t *newTree =  (tree_node_t*)malloc(sizeof(tree_node_t));
    tree_node_t *newTree = new tree_node_t;
    newTree->msg.append(msg);
    newTree->next = NULL;
    newTree->nextFloor = NULL;
    newTree->start = start;
    newTree->end = end;
    return newTree;
}

tree_node_t* DTree::addNext(tree_node_t *node, QString msg,qint32 start,qint32 end){
    //tree_node_t *newNode = (tree_node_t*)malloc(sizeof(tree_node_t));
    tree_node_t *newNode = new tree_node_t;
    newNode->msg.append(msg);
    newNode->next = NULL;
    newNode->nextFloor = NULL;
    newNode->start = start;
    newNode->end = end;
    node->next = newNode;
    return newNode;
}

tree_node_t* DTree::addNextFloor(tree_node_t *node, QString msg,qint32 start,qint32 end){
    tree_node_t *newNode = new tree_node_t;
    //tree_node_t *newNode = (tree_node_t*)malloc(sizeof(tree_node_t));
    newNode->msg.append(msg);
    newNode->next = NULL;
    newNode->nextFloor = NULL;
    newNode->start = start;
    newNode->end = end;
    node->nextFloor = newNode;
    return newNode;
}

void DTree::fillOneNode(tree_node_t *node, QString msg){
    node->msg.clear();
    node->msg.append(msg);
}
