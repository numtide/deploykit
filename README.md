# Deploykit

Execute commands remotely and locally in parallel for a group of hosts with
python. It is meant for short automation tasks. Each line of the output of each
command is prefixed by the hostname of the target.

Here are some important facts about deploykit:

- Local commands and user-defined function: In contrast to many other libraries
  in the space, deploykit allows to also run commands and user-defined
  functions locally in parallel for each host.
- OpenSSH: To retain compatibility with existing configuration, deploykit uses
  the openssh executable for running the commands remotely. 
- Threaded: Deploykit starts a thread per target host run commands and
  user-defined functions and collects their results for inspection. To run
  commands, deploykit wraps around python's subprocess API.

## Example

```
from deploykit import parse_hosts, subprocess.

hosts = parse_hosts("server1,server2,server3")
runs = hosts.run("uptime", stdout=subprocess.PIPE)
for r in runs:
    print(f"The uptime of {r.host.hostname} is {r.result.stdout}")
```

A more comprehensive example explaining all the concepts of the API can be found
[here](https://github.com/numtide/deploykit/blob/main/examples/basic.py).

## Differences to other libraries and tools

- [Fabric](http://fabfile.org): 
  - Deploykit took inspiration from fabric and addresses its limitation that
    local commands cannot be executed in parallel for a range of hosts (i.e. rsync).
    By also allowing to run a function per host it provides higher flexibility. Fabric
    uses [pyinvoke]() as a task runner frontend, so deploykit can be also used in
    combination with the same.
- [Ansible](https://ansible.org): 
  - Deploykit is more lightweight and has a faster startup time.
  - Using python for task definitions allows for more flexibility than yaml.
  - Use ansible if you need declarative configuration management. Use deploykit
    if you want to imperatively quickly execute a series of commands on a number
    of hosts.
