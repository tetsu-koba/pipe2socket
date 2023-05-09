# Read stdin and send to socket
Very simple utility witten in Zig to send streaming data to local area network.
Currently only supports TCP socket.

## Example

Capture video frames by V4L2 and convert them to I420, and encode them to VP8, and sent them by TCP socket.

```
#!/bin/sh -eux

VIDEODEV=/dev/video0
WIDTH=320
HEIGHT=240
FRAMERATE=15
KBPS=1000
GOP=60
HOST=my-mac.local
PORT=8999

v4l2capture $VIDEODEV /dev/stdout $WIDTH $HEIGHT $FRAMERATE YUYV | \
    convert2i420 /dev/stdin /dev/stdout $WIDTH $HEIGHT YUYV | \
    vp8enc /dev/stdin /dev/stdout $WIDTH $HEIGHT $FRAMERATE $KBPS $GOP | \
    pipe2socket tcp://$HOST:$PORT
```

On the reciever

```
ffplay -hide_banner -autoexit tcp://:8999?listen
```

## ToDo

Make this into a package when the official zig package manager is released.
