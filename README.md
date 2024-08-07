FFmpeg README
=============

FFmpeg is a collection of libraries and tools to process multimedia content
such as audio, video, subtitles and related metadata.

## Libraries

* `libavcodec` provides implementation of a wider range of codecs.
* `libavformat` implements streaming protocols, container formats and basic I/O access.
* `libavutil` includes hashers, decompressors and miscellaneous utility functions.
* `libavfilter` provides means to alter decoded audio and video through a directed graph of connected filters.
* `libavdevice` provides an abstraction to access capture and playback devices.
* `libswresample` implements audio mixing and resampling routines.
* `libswscale` implements color conversion and scaling routines.

## Tools

* [ffmpeg](https://ffmpeg.org/ffmpeg.html) is a command line toolbox to
  manipulate, convert and stream multimedia content.
* [ffplay](https://ffmpeg.org/ffplay.html) is a minimalistic multimedia player.
* [ffprobe](https://ffmpeg.org/ffprobe.html) is a simple analysis tool to inspect
  multimedia content.
* Additional small tools such as `aviocat`, `ismindex` and `qt-faststart`.

## Documentation

The offline documentation is available in the **doc/** directory.

The online documentation is available in the main [website](https://ffmpeg.org)
and in the [wiki](https://trac.ffmpeg.org).

### Examples

Coding examples are available in the **doc/examples** directory.

## License

FFmpeg codebase is mainly LGPL-licensed with optional components licensed under
GPL. Please refer to the LICENSE file for detailed information.

## Contributing

Patches should be submitted to the ffmpeg-devel mailing list using
`git format-patch` or `git send-email`. Github pull requests should be
avoided because they are not part of our review process and will be ignored.


## SyncStage

Modules configuration:
```
--disable-everything --enable-libopus \
--enable-encoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis \
--enable-decoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis \
--enable-muxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus \
--enable-demuxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus \
--enable-filter=copy,volume,aformat,aresample,arnndn,channelmap,pan,amerge
```

## Building for Windows

1. Download and install MSYS2 [LINK]("https://www.msys2.org/")
1. __Use MinGW toolchain!__ `"C:\msys64\mingw64.exe"`
1. Clone FFmpeg repo, change to latest `SyncStage` branch i.e. `SyncStage-n6`
1. Install dependencies:
    ```
    pacman -S git
    pacman -S gcc make autotools cmake
    pacman -S zlib
    pacman -S zlib-devel
    pacman -S mingw-w64-x86_64-toolchain
    pacman -S nasm
    pacman -S pkg-config
    pacman -S mingw-w64-x86_64-gnutls mingw-w64-x86_64-opus
    ```
1. Configure 
    ```
    ./configure --prefix=ffmpeg/ --arch=x86_64 --enable-libopus --enable-gnutls --enable-shared --pkg-config-flags="--static" --disable-everything --disable-stripping --disable-optimizations --disable-cuvid --disable-hwaccels --disable-cuda-llvm --disable-ffnvcodec --extra-cflags=-O0 --enable-protocol=srtp,tls,https --enable-encoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis --enable-decoder=pcm_f32le,pcm_s16le,libopus,copy,opus,vorbis --enable-muxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus --enable-demuxer=pcm_f32le,pcm_s16le,rtsp,rtp,ogg,opus --enable-filter=copy,volume,aformat,aresample,arnndn,channelmap,pan,amerge
    ```
1. Build
    ```
    make -j 6 install
    ```
1. The outcome will be located in the `C:\msys64\home\<user>\<git ffmpeg work path>\ffmpeg` directory.
