import argparse
parser = argparse.ArgumentParser(add_help=False)

parser.add_argument('host', nargs='*')
parser.add_argument('-p', action='store', dest='ports', nargs='*', type=int,
                    help='Store port which is ready to scan')
parser.add_argument('-t', action='store', dest='timeout',
                    help='store the timeout of port scan')
parser.add_argument('-o', action="store",
                    dest="output_file", help='save the resule to file')
parser.add_argument('-f', action="store", dest="host_file",
                    help='read the host list from file')
parser.add_argument('-n', action="store",
                    default=10,
                    type=int,
                    help="the number of processes you want to send package",
                    dest="number_of_process")
