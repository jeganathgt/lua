#!/bin/sh

eval "killall ubusd"
eval "ubusd &"
eval "./hostapd_daemon"


#do this for one time
#$ sudo lsmod | grep dummy
#$ sudo modprobe dummy
#$ sudo lsmod | grep dummy
#dummy                  12960  0 
#sudo ip link add wl0 type dummy
#sudo ip link set wl0 up
#sudo ip link add wl1 type dummy
#sudo ip link set wl1 up
#sudo ip link add wl1_1 type dummy
#sudo ip link set wl1_1 up



