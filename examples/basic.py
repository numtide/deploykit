#!/usr/bin/env python3

import subprocess
from deploykit import run, parse_hosts, DeployHost
import argparse


def deploy(host: DeployHost) -> None:
    # Our function will receive a DeployHost object.  This object behaves
    # similar to DeployGroup, except that it is just for one host instead of a
    # group of hosts.

    # This is running locally
    host.run_local("hostname")

    # This is running on the remote machine
    host.run("hostname")

    # We can also use our `DeployHost` object to get connection info for other ssh hosts
    # host.run_local(
    #    f"rsync {' --exclude -vaF --delete -e ssh . {host.user}@{host.host}:/etc/nixos"
    # )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hosts")
    args = parser.parse_args()

    # This command runs on the local machine
    run("hostname")

    # parse_host accepts hosts in comma seperated for form and returns a DeployGroup
    # Hosts can contain username and port numbers
    # i.e. host1,host2,admin@host3:2222
    g = parse_hosts(args.hosts)
    # g will now contain a group of hosts. This is a shorthand for writing
    # g = deploykit.DeployGroup([
    #   DeployHost(host="myhostname"),
    #   DeployHost(host="myhostname2"),
    # ])
    # Let's see what we can do with a `DeployGroup`

    # This command runs locally in parallel for all hosts
    g.run_local("hostname")
    # This commands runs remotely in parallel for all hosts
    g.run("hostname")

    # This function runs in parallel for all hosts. This is useful if you want
    # to run a series of commands per host.
    g.run_function(deploy)

    # By default all functions will throw a subprocess.CalledProcess exception if a command fails.
    # When check=False is passed, instead a subprocess.CompletedProcess value is returned and the user
    # can check the result of command by inspecting the `returncode` attribute
    runs = g.run_local("false", check=False)
    print(runs[0].result.returncode)

    # To capture the output of a command, set stdout/stderr parameter
    runs = g.run_local("hostname", stdout=subprocess.PIPE)
    print(runs[0].result.stdout)


if __name__ == "__main__":
    main()
