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

