#!/usr/bin/env python3

import argparse
import random
import sys
import requests
import time
import multiprocessing
import os


def parse_args():

  """argparse argument parsing"""

  parser = argparse.ArgumentParser(\
    epilog='Example:\n\b' + sys.argv[0] + ' -i hosts_up.list > hosts_http.list',

    # This class enables newlines in help messages
    formatter_class=argparse.RawTextHelpFormatter)


  #parser.error = parser_error

  parser._optionals.title = 'options'

  parser.add_argument('-i', metavar='inputfile', help='This is the only required argument:\nFile with line separated ip addresses to scan\nUse nmap -sL <target>|grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"|sort -u\nto resolve CIDR notation or domain names')
  parser.add_argument('-o', metavar='outputfile', help='Output file, results will be saved here')

  parser.add_argument('-p', metavar='ports', help='Ports to scan\nexpressions such as -p1-10 or -p1,4-10 are valid\ndefault: 0-65535')

  parser.add_argument('--timeout', metavar='seconds', help='Seconds to wait for a response, default: 3')
  parser.add_argument('--delay', metavar='milliseconds', help='Milliseconds to wait between requests\nWith threading the real delay will be different since each thread\nmakes its own requests. However, each thread will have\na random offset to distribute requests evenly on a time basis\ndefault: 0')
  parser.add_argument('--threads', metavar='number', help=F'Thread multiplier: number * <#cores> = threads\nThis is equal to the number of concurrent requests\nYou have {multiprocessing.cpu_count()} cores available\n0 disables threading (default)')
  parser.add_argument('--save-page', metavar='dir', help='Save (HTML) pages in <dir>/<ip-address>:<port>.html')
  parser.add_argument('--save-response', metavar='dir', help='Save the full successful responses in <dir>/<ip-address>:<port>.resp')
  parser.add_argument('--exec', metavar='command', help="Execute <command> after each successful hit.\n'wfuzz -w directories.wordlist http://$target/FUZZ'\n'firefox $html'\nSee --exec help or README.md for all options")
    
  return parser



def exit_err(error_message):

  """ Print an error message and exit """

  print(error_message)
  exit(1)



def write_file(filename, ip_addresses):

  """ Write a list of ip addresses to a file """

  with open(str(filename), 'w') as f:
    for ip_address in ip_addresses:
      f.write(str(ip_address)+"\n")



def read_file(filename):

  """ Read a list of ip addresses from a file """

  with open(str(filename), 'r') as f:
    lines = [i.strip() for i in f.readlines()]
  return lines



def screen(message):
    print(message, file=sys.stderr)



def expand_dash(num_expr):

  """ In a numeric expression expand the dash """

  numbers = [int(i) for i in num_expr.split('-')]

  if len(numbers) != 2 or\
    type(numbers[0]) != int or\
    type(numbers[1]) != int:
    return False

  numbers = [i for i in range(numbers[0], numbers[1]+1)]
  return numbers
  


def parse_port(port_expr):

  """ Parse the port argument, expand '-' and ',', recursive """

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



def scan(targets_list, timeout, delay, threads, output_file, savepagedir, saveresponsedir):

  """ Perform the scan """

  thread_id = random.randint(0,threads)

  # Random time offset for threads

  if threads != 0:
    if delay:
      time_offset = random.randint(0,delay)/1000
    else:
      time_offset = random.randint(1,3000)/1000

    time.sleep(time_offset)


  # Scan

  results_list = []

  for target in targets_list:
    screen(target)
    try:
      if delay:
        time.sleep(delay/1000)
      r = requests.get(F"http://{target}", timeout=timeout)
      print(F"{target}")
      results_list.append(target)

      # Various options for writing results

      if output_file:
        with open(output_file, 'a') as f:
          f.write(target+'\n')

      if savepagedir:
        filename = os.path.join(savepagedir, F"{target}")
        with open(filename, 'w') as f:
          f.write(r.text)

      if saveresponsedir:
        # needs 1st line of response HTTP/1.1 200 OK
        filename = os.path.join(saveresponsedir, F"{target}")
        with open(filename, 'w') as f:

          if r.raw.version == 11:
            http_version = "1.1"
          elif r.raw.version == 10:
            http_version = "1.1"
          else:
            http_version = str(r.raw.version)

          f.write(F"HTTP/{http_version} {r.raw.status} {r.raw.reason}\n")

          for k in r.headers.keys():
            f.write(F"{k}: {r.headers[k]}\n")

          f.write('\n\n'+r.text+'\n')

    except:
      continue

  return results_list



def main():

  """ Init point and main body """


  """ Extract information from command line arguments
  """


  parser = parse_args()
  args = parser.parse_args()
  ports = args.p


  # Resolve input and output file arguments

  if args.i:
    input_file = args.i
  else:
    parser.print_help()
    exit_err("Error: Argument -i inputfile is required")

  if args.o:
    if os.path.exists(args.o):
      os.remove(args.o)
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

  if args.threads:
    if args.threads == 0:
      threads = False
    threads = int(args.threads)
  else:
    threads = False

  if args.save_page:
    if not os.path.exists(args.save_page):
      os.makedirs(args.save_page)
    savepagedir = args.save_page
  else:
    savepagedir = False

  if args.save_response:
    if not os.path.exists(args.save_response):
      os.makedirs(args.save_response)
    saveresponsedir = args.save_response
  else:
    saveresponsedir = False



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


  # No threads
  if threads == False:
    results_list = scan(targets_list, timeout, delay, 0, output_file, savepagedir, saveresponsedir)


  # Yes threads
  else:

    # Prepare multiprocessing
  
    threads = multiprocessing.cpu_count() * threads
    batch_size = int(len(targets_list)/threads)


    # [threads] equally sized batches of target lists

    targets_batch = [[] for i in range(threads)]

    for i in range(threads):
      targets_batch[i] += [targets_list.pop() for j in range(batch_size)]

    while targets_list != 0:
        try:
          for i in range(threads):
            targets_batch[i].append(targets_list.pop())
        except:
          break

    
    # Run parallelized scan

    processes = []
    for i in range(len(targets_batch)):
      p = multiprocessing.Process(target=scan, args = [targets_batch[i], timeout, delay, threads, output_file, savepagedir, saveresponsedir])
      p.start()
      processes.append(p) 
    for p in processes:
      p.join()


    # Collect the results in one list

    #results_list = []
    #for i in results_obj:
    #  results_list += i



if __name__ == "__main__":
  main()
