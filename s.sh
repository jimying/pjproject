#!/bin/bash
BUILD_OUT=$PWD/../build
JOBS=$(nproc)
OS=$(uname -s |  tr '[:upper:]' '[:lower:]')

case $OS in
    *bsd*)
        MAKE=gmake
        ;;
    *linux*)
        MAKE=make
        JOBS=$(nproc)
        ;;
    *)
        MAKE=make
        ;;
esac

#export CFLAGS="-g"
export CFLAGS="-DNDEBUG -fPIC -Wextra -Wno-missing-field-initializers -Wno-unused-label"
    #--with-opus=$HOME/3rd/build
$MAKE distclean
./configure --prefix=$BUILD_OUT/pjsip \
    --enable-epoll \
    --disable-libuuid \
    --disable-gsm-codec \
    --disable-speex-codec --disable-speex-aec \
    --disable-l16-codec \
    --disable-g722-codec \
    --disable-g7221-codec \
    --disable-ilbc-codec \
    --disable-bcg729 \
    --disable-silk \
    --disable-video \
    --disable-libwebrtc \
    --disable-sound \
    --disable-ssl \
    --disable-libsrtp \
    --disable-upnp \
    --disable-opus

rm -f pjlib/include/pj/config_site.h
cp -f config_site.h pjlib/include/pj
$MAKE dep
#$MAKE -C pjlib/build -j  $JOBS
#$MAKE -C pjlib-util/build -j  $JOBS
#$MAKE -C pjnath/build -j  $JOBS
$MAKE -j $JOBS
#$MAKE install
