#!/usr/bin/env python3

import argparse
import random
import sys
import requests
from pprint import pprint



def parse_args():

  """argparse argument parsing"""

  parser = argparse.ArgumentParser(\
    epilog='Example:\n\b' + sys.argv[0] + ' -i hosts_up.list -o hosts_http.list',

    # This class enables newlines in help messages
    formatter_class=argparse.RawTextHelpFormatter)


  #parser.error = parser_error
  parser._optionals.title = 'options'

  parser.add_argument('-i', metavar='inputfile', help='[required] file with line separated ip addresses to scan. \nuse nmap -sL <target>|grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"|sort -u\nto resolve CIDR notation or domain names')

  parser.add_argument('-o', metavar='outputfile', help='[optional] output file for results')

  parser.add_argument('-p', metavar='ports', help='[optional] ports to scan, default: 0-65535\nexpressions such as -p1-10 or -p1,4-10 are valid')

  parser.add_argument('--timeout', metavar='seconds', help='[optional] seconds to wait for a response, default: 3')

  return parser



def exit_err(error_message):

  """Print an error message and exit"""

  print(error_message)
  exit(1)



def write_file(filename, ip_addresses):

  """Write a list of ip addresses to a file"""

  with open(str(filename), 'w') as f:
    for ip_address in ip_addresses:
      f.write(str(ip_address)+"\n")



def read_file(filename):

  """Read a list of ip addresses from a file"""

  with open(str(filename), 'r') as f:
    lines = [i.strip() for i in f.readlines()]
  return lines



def expand_dash(num_expr):

  """In a numeric expression expand the -"""

  numbers = [int(i) for i in num_expr.split('-')]

  if len(numbers) != 2 or\
    type(numbers[0]) != int or\
    type(numbers[1]) != int:
    return False

  numbers = [i for i in range(numbers[0], numbers[1]+1)]
  return numbers
  


def parse_port(port_expr):

  """Parse the port argument, expand '-' and ',', recursive"""

  if ',' in port_expr:
    ports_expanded = []

    for expr in port_expr.split(','):
      ports_expanded += parse_port(expr)
    return ports_expanded


  elif '-' in port_expr:
    ports_expanded = []

    ports_expanded = expand_dash(port_expr)

    if ports_expanded:
      return ports_expanded
    else:
      return False


  else:
    return [int(port_expr)]



def main():

  """Init point and main body"""


  """ Extract information from command line arguments
  """


  parser = parse_args()
  args = parser.parse_args()
  ports = args.p

  # Resolve input and output file arguments

  if args.i:
    input_file = args.i
  else:
    print("Error: Argument -i inputfile is required")
    parser.print_help()
    exit(1)

  if args.o:
    output_file = args.o
  else:
    output_file = False

  ip_list = read_file(input_file)


  # Resolve ports argument

  if args.p:
    port_list = parse_port(args.p)
  else:
    port_list = [i for i in range(0,2**16)]


  # Resolve other arguments

  if args.timeout:
    timeout = int(args.timeout)
  else:
    timeout = 2



  """ Prepare the data
  """


  # Remove duplicates

  ip_list = list(set(ip_list))
  port_list = list(set(port_list))
   

  # Randomize ip and port lists

  random.shuffle(ip_list)
  random.shuffle(port_list)



  """ Perform the scan
  """


  results = {}

  for ip in ip_list:
    print(F"Now scanning {ip}")
    for port in port_list:
      print(port)

      try:
        print(timeout)
        r = requests.get(F"http://{ip}:{port}", timeout=timeout)
        if ip not in results.keys():
          results[ip]=[]
        results[ip].append(port)
        print(F"{ip}:{port}")

      except:
        continue

  if output_file:
    results_list = []
    [[results_list.append(F"{ip}:{port}") for port in results[ip]] for ip in results.keys()]
    write_file(output_file, results_list)




if __name__ == "__main__":
  main()
