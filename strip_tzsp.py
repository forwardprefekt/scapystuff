## Quick script to show how to use TZSP with scapy
## I had a hard time finding a useful example

from scapy.all import *
import time
from tqdm import tqdm_notebook

iface = 'enp0s3'                ## Where to read traffic from
odir = '/data/moloch/raw/'      ## where to write traffic to
maxpackets = 1000              ## when to finish pcap

class pcapwriter():
    
    def __init__(self,maxpackets, odir):
        self.pcapdir = odir
        self.maxpackets = maxpackets
        self.curfile = None
        self.packets = []

    def gettzsp(self, data):
        try: 
            x =  data['TZSP']
            tz = data.getlayer(TZSP)
            enc_pload = tz.get_encapsulated_payload()
            return(enc_pload)
        except:
            pass
        return(data)
        
    def writedata(self, data):
        if self.curfile == None or len(self.packets) >= self.maxpackets:
            self.curfile = "%s/%d.pcap" % (self.pcapdir, int(time.time()) )
            wrpcap(self.curfile, self.packets)
            self.packets = []
        self.packets.append(self.gettzsp(data))
   
load_contrib('tzsp')   #thanks!
bind_layers(UDP, TZSP, sport=37008)
bind_layers(UDP, TZSP, dport=37008)

pw = pcapwriter(maxpackets, odir)   

sniff(iface=iface, prn=pw.writedata, filter="dport == 37008")
