#!/bin/bash
# sourcing scripttol
source $HOME/dotfiles/bin/tools.sh
# error panic
set -o errexit -o pipefail -o noclobber
# enable debug when TRACE=1
if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

function usage() {
  if [ -n "$1" ]; then
    echo  "ERR -> $1\n";
  fi
  echo "Usage: $0 [-h help] "
  echo "  -h, --help   Show this message"
  echo ""
  echo "Example: $0 -h"
  echo "Debug: TRACE=1 $0.sh"
  exit 1
}

# parse params
while [[ "$#" > 0 ]]; do case $1 in
  #-f|--file) FILE="$2";shift;shift;;
  -p|--programs) PROGRAMS=1;shift;;
  -h|--help) usage;shift;;
  *) usage "Unknown parameter passed: $1"; exit 1;;
esac; done

# verify params
#if [ -z "$FILE" ]; then usage "File is not set"; fi;

if [[ $PROGRAMS == "1" ]]; then
  PROGRAMS_CMD="--enable-ffplay --enable-sdl2 --enable-gnutls"
  PREFIX="--prefix=/home/azajas/work/m2e/Aps/FFmpeg/out"
  PROTOCOLS="--enable-protocol=file,srtp,tls,https"
  SHARED="--disable-shared --enable-static "
else
  PROGRAMS_CMD="--disable-programs --enable-gnutls"
  PREFIX="--prefix=/home/azajas/work/m2e/libav-rtsp/lib/ffmpeg"
  SHARED="--enable-shared --disable-static "
  PROTOCOLS="--enable-protocol=srtp,tls,https"
fi

time bear -- ./configure $PROGRAMS_CMD --disable-everything --enable-libopus \
  ${SHARED} \
  --disable-stripping \
  --disable-optimizations --extra-cflags="-O0 -g -fno-omit-frame-pointer -fno-inline" \
  --extra-ldflags="-g" \
  --optflags="-O0" \
  --enable-debug=3  \
  ${PREFIX} \
  ${PROTOCOLS} \
  ${PARSERS} \
  --disable-doc \
  --enable-encoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis \
  --enable-decoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis \
  --enable-muxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus \
  --enable-demuxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus \
  --enable-filter=copy,volume,aformat,aresample,arnndn,channelmap,pan,amerge


tput bel
