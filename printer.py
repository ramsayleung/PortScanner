#!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# author:Samray <samrayleung@gmail.com>
import logging
logging.getLogger("__name__").setLevel(logging.ERROR)


class Printer():

    def __init__(self):
        # default value,in the current dir
        self.filepath = "port_scan_output.txt"

    def list_to_console(self, list):
        for i in list:
            print(i)

    def queue_to_console(self, queue):
        for result in iter(queue.get, ''):
            print(result)

    def queue_to_file(self, queue):
        try:
            with open(self.filepath, 'w') as f:
                for i in iter(queue.get, ''):
                    f.write(i + "\n")
        except IOError as e:
            str(e)

    def list_to_file(self, list):
        try:
            with open(self.filepath, 'w') as f:
                for i in list:
                    f.write(i + "\n")
        except IOError as e:
            str(e)

    def to_console(self, content):
        print(content)

    def to_file(self, content):
        try:
            with open(self.filepath, 'w') as f:
                f.write(content)
        except IOError as e:
            logging.error(str(e))
