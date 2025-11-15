#!/usr/bin/env python3

import socket

import pytest


class Ports:
    def allocate(self) -> socket.socket:
        """
        Allocate a single free port by binding to port 0.

        Returns a bound socket. The caller is responsible for closing the socket
        when done. Use sock.getsockname()[1] to get the allocated port number.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        return sock


@pytest.fixture
def ports() -> Ports:
    return Ports()
