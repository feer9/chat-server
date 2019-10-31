TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        server-main.c

LIBS += -lpthread

HEADERS += \
    server.h
