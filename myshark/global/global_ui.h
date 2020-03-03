#ifndef GLOBAL_UI_H
#define GLOBAL_UI_H
#include <QtCore>

class Global{   //用于将简单解析结果投放到GUI界面上
public:
    enum TableItemPosition:qint8{
        NO = 0,
        TIME,
        SOURCE,
        DESTINATION,
        PROTOCOL,
        LENGTH,
        INFO
    };
};

#endif // GLOBAL_UI_H
