#!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# author:Samray <samrayleung@gmail.com>


def read_host_from_file(filepath):
    try:
        with open(filepath, 'r') as f:
            hosts = f.readlines()
        hosts = [x.strip() for x in hosts]
        return hosts
    except IOError as e:
        str(e)
        hosts = []
        return hosts


def valid_port(port):
    return port > 0 and port < 65536
