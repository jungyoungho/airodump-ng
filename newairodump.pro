TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    makedata.cpp

HEADERS += \
    radio.h \
    save_key_value.h
