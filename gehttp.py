#!/usr/bin/env python3

import argparse
import random
import sys
import requests
import pprint



def parse_args():

  """argparse argument parsing"""

  parser = argparse.ArgumentParser(\
    epilog='Example:\n\b' + sys.argv[0] + ' -i hosts_up.list -o hosts_http.list',

    # This class enables newlines in help messages
    formatter_class=argparse.RawTextHelpFormatter)


  #parser.error = parser_error
  parser._optionals.title = 'arguments'

  parser.add_argument('-i', metavar='INPUT_FILE', help='File with line separated ip addresses to scan. \nUse \'nmap -sL <ip-address>|grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"|sort -u\' to resolve CIDR notation or domain names')

  parser.add_argument('-o', metavar='OUTPUT_FILE', help='Output file for results')

  parser.add_argument('-p', metavar='PORTS', help='Ports to scan, default: 0-65535\nMay use expressions such as -p1-10 or -p1,4-10')

  return parser.parse_args()



def exit_err(error_message):

  """Print an error message and exit"""

  print(error_message)
  exit(1)



def write_file(filename, ip_addresses):

  """Write a list of ip addresses to a file"""

  with open(str(filename), 'w') as f:
    for ip_address in ip_addresses:
      f.write(ip_address)



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


  args = parse_args()
  ports = args.p

  # Resolve input and output file arguments

  if args.i and args.o:
    input_file = args.i
    output_file = args.o
  else:
    exit_err("Error: Arguments -i and -o are required")

  ip_list = read_file(input_file)


  # Resolve ports argument

  if args.p:
    port_list = parse_port(args.p)
  else:
    port_list = [i for i in range(0,2**16)]



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

      try:
        r = requests.get(F"http://{ip}:{port}")
        if ip not in results.keys():
          results[ip]=[]
        results[ip].append(port)
        print(F"{ip}:{port}")

      except:
        continue

  print(results)




if __name__ == "__main__":
  main()
