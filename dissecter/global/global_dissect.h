#ifndef GLOBAL_DISSECT_H
#define GLOBAL_DISSECT_H

#include <QtCore>
#include "netinet/in.h"
#include "time.h"

#include "dtree.h"
#include "dissecter.h"
#include "pro_headers.h"



typedef enum SD:uchar{
     SRC = 0,
     DST
}SD;


#endif // GLOBAL_DISSECT_H
