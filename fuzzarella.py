#!/usr/bin/env python
import sys
import random
import time
import copy
from scapy.all import *
import urllib2
from HTTP import *

def http_request(p):
  if HTTP in p:
    if HTTPRequest in p[HTTP]:
      return True
  return False

#important the http_request be called first
def upcase_host(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req.Host = req.Host.upper()
  return p
  
def remove_host(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    del(req.Host)
  return p

def scramble_host(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req.Host = "{0:s}:{1:d}".format(''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(500)) , random.randint(1024,9000))
  return p

def full_width_url_encoded(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req_array = req.Method.split()
    if len(req_array) > 3:
      raise Exception('Strange Request')
    req.Method = "%s %s %s" % (req_array[0], do_url_encode(req_array[1]),req_array[2])
  return p

#do full width encoding
def do_url_encode(url):
  mutated = ''
  for char in url:
    #blacklisting chars that shouldnt be encoded
    if char not in ['?', '/', '&', '\\', '=', '%', '+']:
      #todo explain magic 0x20
      char = "%%uFF%02x" % ( ord(char) - 0x20 )
    mutated += char
  return mutated

def do_utf8_encoding(url):
  return urllib2.quote(url.encode("utf8"))

def utf8_url_encoded(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    #print req.Method
    req_array = req.Method.split()

    if len(req_array) > 3:
      raise Exception('Strange Request')
    req.Method =  "%s %s %s" %(req_array[0], do_utf8_encoding(req_array[1]), req_array[2])
  return p


def run_mutations(t, pkts):

    def generic_mutation(t, mutation_func):
      print "running %s" % t
      mutated_packets = [ mutation_func(pkt) for pkt in copy.deepcopy(pkts)]
      write_mangled_packets("%s.pcap" % t, mutated_packets)

    #default to upcase_host
    return {
        "upcase_host" : generic_mutation("upcase_host", upcase_host),
        "full_width_url_encoding" : generic_mutation("full_width_url_encoded",full_width_url_encoded),
        "remove_host": generic_mutation("remove_host",remove_host),
        "utf8_encoding" : generic_mutation("utf8_url_encoded", utf8_url_encoded)
    }.get(t,"upcase_host")


def write_mangled_packets(mangle_type,pkts):
  wrpcap(mangle_type,pkts)
  pkts = []

if __name__ == '__main__':

  if len(sys.argv) <= 1:
	  print "%s <pcap>" % sys.argv[0]
	  sys.exit(1)

  packets = rdpcap(sys.argv[1])
  run_mutations("upcase_host",packets)