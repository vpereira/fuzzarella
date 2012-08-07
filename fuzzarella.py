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
  def change(c):
    if c not in ['?', '/', '&', '\\', '=', '%', '+']: 
      return "%%uFF%02x" % ( ord(c) - 0x20)
    else: return c
  mutated = [ change(c) for c in list(url) ]
  return "".join(mutated)

def do_utf8_encoding(url):
  return urllib2.quote(url.encode("utf8"))

def utf8_url_encoded(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req_array = req.Method.split()

    if len(req_array) > 3:
      raise Exception('Strange Request')
    req.Method =  "%s %s %s" %(req_array[0], do_utf8_encoding(req_array[1]), req_array[2])
  return p


def insert_null_to_request(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req_array = req.Method.split()
    if len(req_array) > 3:
      raise Exception('Strange Request')
    req.Method =  "%s %%00%s%%00 %s" %(req_array[0], req_array[1], req_array[2])
  return p


 
def run_mutations(t, pkts):
    """
      Generic Mutation Function
      you must pass the type and mutation_func. Normally they are equal but one
      is string. There is nothing like the magic ruby "send"?
    """
    def generic_mutation(tt, mutation_func):
      print "generatng %s" % tt
      mutated_packets = [ mutation_func(pkt) for pkt in copy.deepcopy(pkts)]
      write_mangled_packets("%s.pcap" % tt, mutated_packets)

    if t == "upcase_host":
      generic_mutation("upcase_host",upcase_host)
    elif t == "remove_host":
      generic_mutation("remove_host", remove_host)
    elif t == "insert_null_to_request":
      generic_mutation("insert_null_to_request", insert_null_to_request)
    elif t == "full_width_url_encoding":
      generic_mutation("full_width_url_encoded",full_width_url_encoded)
    elif t == "scramble_host":
      generic_mutation("scramble_host",scramble_host)
    elif t == "utf8_encoding":
      generic_mutation("utf8_url_encoded", utf8_url_encoded)
    else: #ALL
      generic_mutation("full_width_url_encoded",full_width_url_encoded)     
      generic_mutation("remove_host", remove_host)
      generic_mutation("insert_null_to_request", insert_null_to_request)     
      generic_mutation("utf8_url_encoded", utf8_url_encoded)  
      generic_mutation("upcase_host",upcase_host)
      generic_mutation("scramble_host",scramble_host)
    #TODO if you are able to FIX this ninja-code, please do it
    #it calls all the functions, it should call just the value from the choosen
    #key wierd :-/
    #default to upcase_host
    #return {
    #    "upcase_host" : generic_mutation("upcase_host", upcase_host),
    #    "insert_null_to_request" : generic_mutation("insert_null_to_request", insert_null_to_request),
    #    "full_width_url_encoding" : generic_mutation("full_width_url_encoded",full_width_url_encoded),
    #    "remove_host": generic_mutation("remove_host",remove_host),
    #    "scramble_host": generic_mutation("scramble_host",scramble_host),
    #    "utf8_encoding" : generic_mutation("utf8_url_encoded", utf8_url_encoded)
    #}.get(t,"upcase_host")


def write_mangled_packets(mangle_type,pkts):
  wrpcap(mangle_type,pkts)
  del pkts[:]
  
if __name__ == '__main__':

  if len(sys.argv) <= 1:
	  print "%s <pcap>" % sys.argv[0]
	  sys.exit(1)

  packets = rdpcap(sys.argv[1])
  run_mutations("all",packets)

