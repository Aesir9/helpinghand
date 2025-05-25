#!/bin/bash

echo "[*] SSH Key finder"
find -L /home -type f -size +200c -size -14000c -exec grep -l -m 1 -E '^----[-| ]BEGIN .{0,15}PRIVATE KEY' {} + 2>/dev/null

printf "\n[*] Kerberos Ticket finder\n"
find / -name *keytab* -ls 2>/dev/null
find / -name *krb5cc* -ls 2>/dev/null

printf "\n[*] Known Hosts\n"
find -L /home -type f -name *known_hosts -exec cat {} \; 2>/dev/null

printf "\n[*] Bash History\n"
find -L /home -type f -name .bash_history -exec tail -n 20 {} \; 2>/dev/null

printf "\n[*] Network infos\n"
host `hostname` 
cat /etc/hosts
ip -brief a

printf "\n[*] SSH Auth Sockets (scuffed)\n"
cat /proc/*/environ 2>/dev/null | grep -ao SSH_AUTH_SOCK[^:] 2>/dev/null*