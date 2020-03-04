#ifndef DISSECTT_H
#define DISSECTT_H

#include <QObject>
#include <QThread>
#include <QMutex>
#include "capture.h"
#include "../../global.h"
#include "loader.h"

class Dissect:public QThread
{
    Q_OBJECT
public:
    Dissect(Capture *capture);
    ~Dissect();
    dissect_result_list_t *GetDissectResList();
    Loader *GetLoader();

protected:
    void run() Q_DECL_OVERRIDE;
    void clear();   //在重新开始前，清理LDisRes

private:
    dissect_result_list_t *dissect_result_list;
    Capture *capture;
    Loader *loader;

public slots:
    void StartDissect();
    void DissectOnePacket(qint64 No);

signals:
    void onePacketDissected(dissect_result_t *DisRes);
    void print(dissect_result_t *res);
};

#endif // DISSECTT_H
