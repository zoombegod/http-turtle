#!/usr/bin/env python3

import argparse
import random
import sys
import requests
import time
from pprint import pprint



def parse_args():

  """argparse argument parsing"""

  parser = argparse.ArgumentParser(\
    epilog='Example:\n\b' + sys.argv[0] + ' -i hosts_up.list -o hosts_http.list',

    # This class enables newlines in help messages
    formatter_class=argparse.RawTextHelpFormatter)


  #parser.error = parser_error
  parser._optionals.title = 'options'

  parser.add_argument('-i', metavar='inputfile', help='This is the only required argument:\nFile with line separated ip addresses to scan. \nUse nmap -sL <target>|grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"|sort -u\nto resolve CIDR notation or domain names')

  parser.add_argument('-o', metavar='outputfile', help='Output file for results')

  parser.add_argument('-p', metavar='ports', help='Ports to scan, default: 0-65535\nexpressions such as -p1-10 or -p1,4-10 are valid')

  parser.add_argument('--timeout', metavar='seconds', help='Seconds to wait for a response, default: 3')
  parser.add_argument('--delay', metavar='milliseconds', help='Milliseconds to wait between requests, default: 0')

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
    timeout = 3

  if args.delay:
    delay = int(args.delay)
  else:
    delay = False



  """ Prepare the data
  """


  # Remove duplicates

  ip_list = list(set(ip_list))
  port_list = list(set(port_list))
   

  # Combine in a list and randomize

  targets_list = []
  [[targets_list.append(F"{ip}:{port}") for port in port_list] for ip in ip_list]
  random.shuffle(targets_list)



  """ Perform the scan
  """


  results_list = []
  current_target = ""

  for target in targets_list:
    ip = target.split(":")[0]

    if current_target != ip:
      current_target = ip
      print(F"Sanning {ip}")

    try:
      if delay:
        time.sleep(delay/1000)
      r = requests.get(F"http://{target}", timeout=timeout)
      results_list.append(target)
      print(F"{target}")

    except:
      continue

  if output_file:
    results_list = []
    [[results_list.append(F"{ip}:{port}") for port in results[ip]] for ip in results.keys()]
    write_file(output_file, results_list)




if __name__ == "__main__":
  main()
