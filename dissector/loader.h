#ifndef LOAD_H
#define LOAD_H

#include <QObject>
#include "dissecter.h"

class Loader:public QObject
{
    Q_OBJECT
public:
    Loader();
    Dissecter *GetDissecter(qint32 key);

private:
    QHash<qint32,Dissecter*> dissecterHash;
};

#endif // LOAD_H
