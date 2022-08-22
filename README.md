# Deploykit

A Python library that executes commands in parallel, locally and remotely,
over a group of hosts.

This library has been extracted from existing projects where it was used as a
basis to create deployment scripts. It's a bit like a mini Ansible, without
the YAML overhead, and usable as a simple composable library.

Here are some important facts about deploykit:

- Local commands and user-defined function: In contrast to many other libraries
  in the space, deploykit allows to also run commands and user-defined
  functions locally in parallel for each host.
- OpenSSH: To retain compatibility with existing configuration, deploykit uses
  the openssh executable for running the commands remotely. 
- Threaded: Deploykit starts a thread per target host run commands and
  user-defined functions and collects their results for inspection. To run
  commands, deploykit wraps around python's subprocess API.
- Clean output: command outputs are prefixed by the hostname of the target.

## Example

```python
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
  - Using python for task definitions allows for more flexibility than YAML.
  - Use ansible if you need declarative configuration management. Use deploykit
    if you want to imperatively quickly execute a series of commands on a number
    of hosts.

## Contributing

Contributions and discussions are welcome. Please make sure to send a WIP PR
or issue before doing large refactors, so your work doesn't get wasted (in
case of disagreement).

## License

This project is copyright Numtide and contributors, and licensed under the
[MIT](LICENSE).
