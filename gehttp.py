#!/usr/bin/env python3

import argparse
import random
import sys
import requests
import time
import multiprocessing
import os
import subprocess
import signal


STATUS_FILE = ".gehttp_status"



def cleanup():

  # Remove status file

  files = os.listdir(".")
  files = [f for f in files if STATUS_FILE in f]

  for file in files:
    os.remove(file)



def dircheck(directory):

  # Handle direcory creation and more

  if not os.path.exists(directory):
    os.makedirs(directory)
    return

  if os.path.isfile(directory):
      exit_err(F"Error: directory {directory} is a file")



def sigint_handler_main(sig_num, i):

  # Do nothing
  return



def sigint_handler_thread(sig_num, i):

  """ Handle SIGINT
  """

  os.kill(os.getpid(), signal.SIGKILL)
  sys.exit()
  exit()



def parse_args():

  """ Argument parsing by argparse """

  parser = argparse.ArgumentParser(\
    epilog='Example:\n\b' + sys.argv[0] + ' -i hosts_up.list > hosts_http.list',

    # Enable newlines in help description
    formatter_class=argparse.RawTextHelpFormatter)


  parser._optionals.title = 'options'

  parser.add_argument('-i', metavar='inputfile', help='This is the only required argument:\nFile with line separated ip addresses or domain names to scan\nUse nmap -sL <target>|grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"|sort -u\nto resolve CIDR notation')
  parser.add_argument('-o', metavar='outputfile', help='Output file, results will be saved here')

  parser.add_argument('-p', metavar='ports', help='Ports to scan\nexpressions such as -p1-10 or -p1,4-10 are valid\ndefault: 0-65535')

  parser.add_argument('--timeout', metavar='seconds', help='Seconds to wait for a response, default: 3')

  parser.add_argument('--delay', metavar='milliseconds', help='Milliseconds to wait between requests\nWith threading the real delay will be different since each thread\nmakes its own requests. However, each thread will have\na random offset to distribute requests evenly on a time basis\ndefault: 0')

  parser.add_argument('--threads', metavar='number', help=F'Thread multiplier: number * <#cores> = threads\nnumber can be an integer or a float\nthreads is equal to the maximum of concurrent requests\nYou have {multiprocessing.cpu_count()} cores available\n0 disables threading (default)')

  parser.add_argument('--save-html', metavar='dir', help='Save (mostly HTML) pages in <dir>/<ip-address>:<port>.html')

  parser.add_argument('--save-response', metavar='dir', help='Save the full successful responses in <dir>/<ip-address>:<port>.resp')

  parser.add_argument('--exec', metavar='command', help="Execute <command> after each successful hit.\n'wfuzz -w directories.wordlist http://%target/FUZZ'\n'firefox %html'\nSee --exec help or README.md for all options")

  parser.add_argument('--stdout', action="store_true", help="Write results to stdout, additionally.\nIf used together with --exec the output of the command will be merged")

  parser.add_argument('--targets', action='store_true', help='Treat entries of inputfile as <ip>:<port> format')

  return parser



def exit_err(error_message):

  """ Print an error message and exit """

  print(error_message)
  exit(1)



def write_file(filename, lines):

  """ Write a list of lines to a file """

  with open(str(filename), 'w') as f:
    for line in lines:
      f.write(str(line)+"\n")



def read_file(filename):

  """ Read a list of ip addresses from a file """

  with open(str(filename), 'r') as f:
    lines = [i.strip() for i in f.readlines()]

  return lines



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

  """ Parse the port argument, expand expressions, recursive """

  # Expand comma

  if ',' in port_expr:
    ports_expanded = []

    for expr in port_expr.split(','):
      ports_expanded += parse_port(expr)

    return ports_expanded


  # Expand dash

  elif '-' in port_expr:
    ports_expanded = []

    ports_expanded = expand_dash(port_expr)

    if ports_expanded:
      return ports_expanded

    else:
      return False


  # Nothing to expand, termination condition

  else:
    return [int(port_expr)]



def scan(targets_list, timeout, delay, threads, output_file, save_html_dir, save_response_dir, execute_command, stdout, thread_id):

  """ Scan a given list of targets for http services """

  """ Time offset
  """

  # If threaded wait for a random time to distribute
  # requests evenly by offsetting the starting time

  if threads != 0:
    if delay:
      time_offset = random.randint(0,delay)/1000
    else:
      time_offset = random.randint(1,3000)/1000

    time.sleep(time_offset)


  """ Main loop over all targets
  """

  t_start = 99
  for target in targets_list:

    # Write the progress to the thread status file

    if threads:
      with open(STATUS_FILE+"_thread_"+str(thread_id), 'w') as f:
        f.write(str(int(targets_list.index(target)/len(targets_list)*100)))


    """ Print status message
    """

    t_end = time.time()

    ## Threaded version
    if threads and t_end - t_start >= 2 and thread_id == 0:

      t_start = time.time()


      # Gather data from all thread status files

      threads_stat = {}

      for i in range(threads):
        thread_file = STATUS_FILE+"_thread_"+str(i)

        if os.path.exists(thread_file):
          with open(thread_file, 'r') as f:
            progress = f.read()

          if progress.isnumeric():
            threads_stat[i] = progress


      # Calculate the overall progress

      stats = [int(threads_stat[k]) for k in threads_stat.keys()]


      # Print to stderr

      print(F"\rProgress: {int(sum(stats)/len(stats))}%", end='', file=sys.stderr)



    ## Unthreaded version
    elif not threads and t_end - t_start >= 2:

      t_start = time.time()

      print(F"\rProgress: {int(targets_list.index(target)/len(targets_list)*100)}%", end='', file=sys.stderr)


    """ Request HTTP on a special port
    """

    try:

      """ Delay
      """

      if delay:
        time.sleep(delay/1000)


      """ Request
      """

      r = requests.get(F"http://{target}", timeout=timeout)


      """ Command line options
      """

      if stdout:
        print('\n'+target)

      if output_file:
        with open(output_file, 'a') as f:
          f.write(target+'\n')

      if save_html_dir:
        page_filename = os.path.join(save_html_dir, F"{target}")
        with open(page_filename, 'w') as f:
          f.write(r.text+'\n')

      if save_response_dir:
        response_filename = os.path.join(save_response_dir, F"{target}")
        with open(response_filename, 'w') as f:

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

      if execute_command:
        execute_command = execute_command\
          .replace('%target',target)\
          .replace('%ip',target.split(':')[0])\
          .replace('%port',target.split(':')[1])\
          .replace('%status',str(r.raw.status))\
          .replace('%response',response_filename)\
          .replace('%html',page_filename)\

        os.system(execute_command)

    except:
      continue


def main():

  """ Initialize program, parse arguments, execute """


  # On SIGINT kill self with SIGKILL

  signal.signal(signal.SIGINT, sigint_handler_thread)


  """ Extract information from command line arguments
  """

  parser = parse_args()
  args = parser.parse_args()
  ports = args.p


  # Input and output file

  if args.i:
    if os.path.exists(args.i) and os.path.isfile(args.i):
        input_file = args.i
    else:
        exit_err(F"Error: {args.i} does not exist ot is not a file")
  else:
    parser.print_help()
    exit_err("Error: Argument -i inputfile is required")

  if args.o:
    if os.path.exists(args.o):
      os.remove(args.o)
    output_file = args.o
  else:
    output_file = False


  # Ports

  if args.p:
    port_list = parse_port(args.p)
  else:
    port_list = [i for i in range(0,2**16)]


  # Timeout, delay, threads

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
    threads = float(args.threads)
  else:
    threads = False


  # Save page, save response, exec, stdout

  if args.save_html:
    dircheck(args.save_html)
    save_html_dir = args.save_html
  else:
    save_html_dir = False

  if args.save_response:
    dircheck(args.save_response)
    save_response_dir = args.save_response
  else:
    save_response_dir = False

  if args.exec:
    if '%html' in args.exec and not save_html_dir:
        exit_err("Error: variable %html used in --exec but --save-html is empty")
    if '%response' in args.exec and not save_response_dir:
        exit_err("Error: variable %response used in --exec but --save-response is empty")
    execute_command = args.exec
  else:
    execute_command = False

  if args.stdout:
    stdout = True
  else:
    stdout = False



  """ Prepare the data
  """

  ip_list = read_file(input_file)


  # Check format

  if not args.targets:
      for i in ip_list:
          if ':' in i:
              exit_err(F"Error: Bad format {i}")


  # Remove duplicates

  ip_list = list(set(ip_list))
  port_list = list(set(port_list))


  # Combine in a list

  if args.targets:
    targets_list = ip_list

  else:
    targets_list = []
    [[targets_list.append(F"{ip}:{port}") for port in port_list] for ip in ip_list]


  # Randomize

  random.shuffle(targets_list)


  """ Start the scan
  """

  # NO threads
  if threads == False:
    scan(targets_list, timeout, delay, threads, output_file, save_html_dir, save_response_dir, execute_command, stdout, 0)


  # YES threads
  else:

    # Init multiprocessing

    threads = int(multiprocessing.cpu_count() * threads)
    batch_size = int(len(targets_list)/threads)


    # Create [threads] equally sized batches

    targets_batch = [[] for i in range(threads)]

    for i in range(threads):
      targets_batch[i] += [targets_list.pop() for j in range(batch_size)]

    while targets_list != 0:
        try:
          for i in range(threads):
            targets_batch[i].append(targets_list.pop())
        except:
          break


    # Start threads

    processes = []
    thread_id = 0

    for i in range(len(targets_batch)):

      p = multiprocessing.Process(target=scan, args = [targets_batch[i], timeout, delay, threads, output_file, save_html_dir, save_response_dir, execute_command, stdout, thread_id])

      p.start()

      processes.append(p)

      thread_id += 1


    # SIGINT handler of the main process, performs cleanup

    signal.signal(signal.SIGINT, sigint_handler_main)


    # Wait for threads to finish

    for p in processes:
      if p.is_alive():
        p.join()

    cleanup()


  """ End of program
  """

  print("", file=sys.stderr)
  exit(0)



if __name__ == "__main__":
  main()
