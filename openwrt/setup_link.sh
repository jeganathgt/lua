#!/bin/sh

ip link add eth0 type dummy
ip link add eth1 type dummy
ip link add wl0 type dummy
ip link add wl1 type dummy
ip link add wl0_1 type dummy
ip link add wl0_2 type dummy
ip link add wl0_3 type dummy
ip link add wl1_1 type dummy
ip link add wl1_2 type dummy
ip link add wl1_3 type dummy
sudo ip link add wds1_1_1 type dummy
sudo ip link add wds1_2_1 type dummy

brctl addbr br-lan
brctl addbr br-guest
brctl addbr br-guest2

brctl addif br-lan eth0
brctl addif br-lan eth1
brctl addif br-lan wl0
brctl addif br-lan wl1
brctl addif br-lan wl0_1 
brctl addif br-lan wl0_2
brctl addif br-lan wl0_3
brctl addif br-lan wl1_1
brctl addif br-lan wl1_2
brctl addif br-lan wl1_3
brctl addif br-lan wds1_1_1
brctl addif br-lan wds1_2_1

ifconfig  eth0 up
ifconfig  eth1 up
ifconfig  wl0 up
ifconfig  wl1 up
ifconfig  wl0_1  up
ifconfig  wl0_2 up
ifconfig  wl0_3 up
ifconfig  wl1_1 up
ifconfig  wl1_2 up
ifconfig  wl1_3 up
ifconfig  wds1_1_1  up
ifconfig  wds1_2_1  up
