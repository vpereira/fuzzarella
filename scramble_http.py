import sys
import random
import time

from scapy.all import *

from HTTP import *

def http_request(p):
  if HTTP in p:
    if HTTPRequest in p[HTTP]:
      return True
  return False

#important the http_request be called first
def upcase(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req.Host = req.Host.upper()
  return p
  
def del_host(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    del(req.Host)
  return p

def scramble_host(p):
  if http_request(p):
    req = p[HTTP][HTTPRequest]
    req.Host = "{0:s}:{1:d}".format(''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(500)) , random.randint(1024,9000))
  return p

packets = rdpcap('fb.pcap')

upcased_packets = [ upcase(pkt) for pkt in packets]
wrpcap('upcased.pcap',upcased_packets)
upcased_packets = []

scrambled_host_packets = [ scramble_host(pkt) for pkt in packets]
wrpcap('scrambled.pcap',scrambled_host_packets)

scrambled_host_packets = []

deleted_hosts_packets = [ del_host(pkt) for pkt in packets]
wrpcap('deleted.pcap',deleted_hosts_packets)

