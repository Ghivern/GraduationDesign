/****************************************************************************
** Meta object code from reading C++ file 'dissect.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.14.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "threads/dissect.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'dissect.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.14.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Dissect_t {
    QByteArrayData data[8];
    char stringdata0[76];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Dissect_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Dissect_t qt_meta_stringdata_Dissect = {
    {
QT_MOC_LITERAL(0, 0, 7), // "Dissect"
QT_MOC_LITERAL(1, 8, 18), // "onePacketDissected"
QT_MOC_LITERAL(2, 27, 0), // ""
QT_MOC_LITERAL(3, 28, 17), // "dissect_result_t*"
QT_MOC_LITERAL(4, 46, 6), // "DisRes"
QT_MOC_LITERAL(5, 53, 5), // "print"
QT_MOC_LITERAL(6, 59, 3), // "res"
QT_MOC_LITERAL(7, 63, 12) // "StartDissect"

    },
    "Dissect\0onePacketDissected\0\0"
    "dissect_result_t*\0DisRes\0print\0res\0"
    "StartDissect"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Dissect[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   29,    2, 0x06 /* Public */,
       5,    1,   32,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       7,    0,   35,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 3,    6,

 // slots: parameters
    QMetaType::Void,

       0        // eod
};

void Dissect::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Dissect *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->onePacketDissected((*reinterpret_cast< dissect_result_t*(*)>(_a[1]))); break;
        case 1: _t->print((*reinterpret_cast< dissect_result_t*(*)>(_a[1]))); break;
        case 2: _t->StartDissect(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Dissect::*)(dissect_result_t * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Dissect::onePacketDissected)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Dissect::*)(dissect_result_t * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Dissect::print)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Dissect::staticMetaObject = { {
    QMetaObject::SuperData::link<QThread::staticMetaObject>(),
    qt_meta_stringdata_Dissect.data,
    qt_meta_data_Dissect,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Dissect::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Dissect::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Dissect.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int Dissect::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void Dissect::onePacketDissected(dissect_result_t * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Dissect::print(dissect_result_t * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE