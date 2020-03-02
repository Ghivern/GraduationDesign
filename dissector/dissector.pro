QT -= gui

TEMPLATE = lib
DEFINES += DISSECT3_1_LIBRARY

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    dissecter.cpp \
    dissecters/dissecter_arp.cpp \
    dissecters/dissecter_eth.cpp \
    dissecters/dissecter_frame.cpp \
    dissecters/dissecter_ip.cpp \
    dissecters/dissecter_tcp.cpp \
    dissecters/dissecter_udp.cpp \
    dtree.cpp \
    loader.cpp

HEADERS += \
    dissecter.h \
    dissecters/dissecter_arp.h \
    dissecters/dissecter_eth.h \
    dissecters/dissecter_frame.h \
    dissecters/dissecter_ip.h \
    dissecters/dissecter_tcp.h \
    dissecters/dissecter_udp.h \
    dtree.h \
    ../global.h \
    global/global_dissect.h \
    global/pro_headers.h \
    loader.h

LIBS += -lpcap

DESTDIR = ../lib

unix:OBJECTS_DIR = ../tmp

# Default rules for deployment.
#unix {
#    target.path = /usr/lib
#}
#!isEmpty(target.path): INSTALLS += target
