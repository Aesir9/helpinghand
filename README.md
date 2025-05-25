# Helpinghand

A terminal assistant which helps you with pentesting. The goal of this tool is to automate repetitive tasks, most things are just helper scripts which generate a command which then gets placed into the clipboard, other tools are fully automated with the help of tmux sessions. This tool is very opinionated and should be used as inspiration for your own tooling. You can try to use my workflow but it may not be the correct one for you.

Helpinghand will store credentials and hosts in a sqlite file called `helpinghand.db` this file will always be created in the current working directory and can be viewed as a project file. 

## Installation

1. Clone the repo
2. Install poetry https://python-poetry.org/docs/
3. Install dependecies
```
cd helpinghand
poetry install
``` 
4. Run the scripts - this will create in the current working directory a new sqlite database.
```
source .venv/bin/activate
python3 ./helpinghand.py
```

5. Create shell alias
```
hh='~helpinghand/.venv/bin/python ~/helpinghand/helpinghand.py'
```


## Getting Started

First hosts need to be added, this can be done with `host scan`, follow the on screen prompts. Multiple IP's can be entered delimted either by `,` or a newline. Onced added, helpinghand will scan them with `nmap`, the `cli` will have new prompts:

``` 
'[Q:{queued_tasks}/R:{running_tasks}/F:{finished_tasks}]
``` 
This will disappear if all tasks are done.

Interact with  hosts

- `host` 
- `host full` 
- `host add` 
- `host edit` 
- `host delete` 
- `host info <int>` 

See more in the help menu

## Help Menu

```
[*] Misc
sliver setup        Basic Sliver setup
clear               Clears the database
help                Displays this help menu
verify tools        Verify third party tools
change-octet        Hyper specific to OSEP
override ip         Changes the IP in all of the tools to the new specified one
hostsfile           Generates a /etc/hosts file template
gen markdown        Generates Markdown Templates for Hosts
gen mdtable         Generates Markdown Table for Obsidian
discover network    Discovers the targeted network
exit                
serve               New way to serve files?

[*] Windows
win powerview       
win powerup         
win privesccheck    itm4n PrivescCheck
win shell           Optional port
win pillage         
win peas            
win enum            
win ligolo          
win powermad        
win sharphound      
win powerhound      executes SharpHound.ps1
win autohound       Executes SharpHound and exfiltrates the zip file
win beacon          Deploys OneForAll stager
win godpotato       Exploits SeImpersonatePrivilege
win printspoofer    Exploits SeImpersonatePrivilege
win pwn             Mutli Enum Script
win nightmare       CVE-2021-1675
win mssqland        
win sliverhound     Run bloodhound via sliver beacon
win vpn_healtcheck  Hyper specific for OffSec VPN
win applocker       Custom AWL InstallUtil bypass gain access to a unconstrained PowerShell with Amsi Bypass
win rubeus          
win serve           win serve <file> | Hosts any file and generates a command to download it
win psexec          Sysinternals PSExec
win fodhelper       Abuse Fodhelper to bypass UAC
win download        Exfiltrates the current working directory
win spoolsample     SpoolSample to coerce spooler service
win everything      Everything Binary to search for files
win lazagne         
win sigmapotato     
win amsibypass      Basic Amsi Bypass for PowerShell
win uac             
win local           
win proof           

[*] Linux
lin shell           lin shell <port=4444> | Optional port defaults to 4444
lin beacon          
lin pillage         
lin pspy            
lin peas            
lin enum            My own enum script for Linux
lin ligolo          
lin traitor         
lin download        Exfiltrates the current working directory
lin local           
lin proof           

[*] Credentials
creds add           
creds edit          
creds delete        
creds use           
creds spray username allprotoThis will spray the username for all protocals: ssh, smb, rdp, winrm
creds spray username
creds               creds <filter:str> | Optional filter searches in domain, username

[*] Host
host full           
host add            
host edit           
host delete         
host info           host info <id> | displays nmap scan results
host scan           Adds a new host and scans it with nmap, you can specify multiple IPs delimited by a comma
host ffuf           
host mark           Mark host as compromised
host web            Shows all possible websites
host                host <filter:str> | Optional filter searches in ports, ip, name, users
``` 