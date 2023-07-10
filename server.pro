TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c11

SOURCES += \
        server-main.c

LIBS += -lpthread

HEADERS += \
    server.h
