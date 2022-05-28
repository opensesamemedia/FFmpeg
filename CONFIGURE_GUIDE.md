# FFmpeg is compiled with:
```
   --disable-everything \
   --disable-programs \
   --disable-docs \
   --enable-encoder=pcm_f32le,libopus \
   --enable-decoder=pcm_f32le,libopus \
   --enable-muxer=pcm_f32le,rtsp,rtp \
   --enable-demuxer=pcm_f32le,rtsp,rtp \
   --enable-filter=abuffer,volume,aformat,abuffersink \
   --enable-gnutls --enable-libopus --disable-gpl
```
