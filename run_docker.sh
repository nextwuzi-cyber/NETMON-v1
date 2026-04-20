#!/bin/bash

xhost +local:docker > /dev/null

echo "[*] Building Docker image..."
docker build -t netmonitor .

echo "[*] Launching netmonitor..."
docker run -it --rm \
    --privileged \
    --network host \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    netmonitor

xhost -local:docker > /dev/null
