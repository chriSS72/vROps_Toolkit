#!/opt/vmware/bin/python


"""
Author:  Christian Soto (chsoto@vmware.com)
"""
##### BEGIN IMPORTS #####

import os
import sys
import json
import subprocess
import re
import pprint
import ssl
import textwrap
from datetime import datetime, timedelta
from codecs import encode, decode
from time import sleep
import socket
try:
    # Python 3 hack.
    import urllib.request as urllib2
    import urllib.parse as urlparses
except ImportError:
    import urllib2
    import urlparse

today = datetime.now()
today = today.strftime("%d-%m-%Y")

vcsa_kblink = "https://kb.vmware.com/s/article/76719"
win_kblink = "https://kb.vmware.com/s/article/79263"
VMENV = os.environ
##### END IMPORTS #####

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

commandsTitle=["DATE",
        "UPTIME",
        "HOSTNAME",
        "vROPS VERSION",
        "IP ADDRESS",
        "VM SIZING",
        "TOP",
        "STORAGE",
        "LOCAL OS ACCOUNTS",
        "CERTIFICATES",
        "CLUSTER STATUS",
        "VROPS SERVICES STATUS"]

class host:
    def dateCMD(host_address):
        print(subprocess_cmd("date", host_address))

    def uptimeCMD(host_address):
        print(subprocess_cmd("uptime", host_address))

    def hostnameCMD(host_address):
        print(subprocess_cmd("hostname -f", host_address))

    def ip_addressCMD(host_address):
        print(subprocess_cmd("ifconfig eth0", host_address))

    def vm_sizingCMD(host_address):
        print("vCPUS:")
        print(subprocess_cmd("grep -wc processor /proc/cpuinfo", host_address))
        print("RAM:")
        print(subprocess_cmd("grep 'MemTotal' /proc/meminfo", host_address))
        print(subprocess_cmd("grep 'MemFree' /proc/meminfo", host_address))
        print(subprocess_cmd("grep 'MemAvailable' /proc/meminfo", host_address))
        print(subprocess_cmd("grep 'SwapTotal' /proc/meminfo", host_address))
        print(subprocess_cmd("grep 'SwapFree' /proc/meminfo", host_address))
    
    def topCMD(host_address):
        print(subprocess_cmd("top -n 1 -b | head -15", host_address))

    def vROps_versionCMD(host_address):
        print(subprocess_cmd("rpm -qa | grep --color=never -i 'vmware-vcops-[0-9]'", host_address))

    def local_OS_accountCMD(host_address):
        print(bcolors.BOLD + "--ROOT ACCOUNT--" + bcolors.ENDC)
        print(subprocess_cmd("chage -l root", host_address))
        print(subprocess_cmd("pam_tally2 -u root", host_address))

        print(bcolors.BOLD + "--ADMIN ACCOUNT--" + bcolors.ENDC)
        print(subprocess_cmd("chage -l admin", host_address))
        print(subprocess_cmd("pam_tally2 -u admin", host_address))

        print(bcolors.BOLD + "--POSTGRES ACCOUNT--" + bcolors.ENDC)
        print(subprocess_cmd("chage -l postgres", host_address))
        print(subprocess_cmd("pam_tally2 -u postgres", host_address))

    def storageCMD(host_address):
        print(subprocess_cmd("df -h", host_address))
        print(bcolors.WARNING + "--HEAPDUMPS--" + bcolors.ENDC)
        print(subprocess_cmd("ls -l /storage/db/vcops/heapdump/", host_address))

    def node_type(host_address):
        remote_collector=subprocess_cmd("grep remotecollectorroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties", host_address)
        admin=subprocess_cmd("grep -i adminroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties", host_address)
        if (remote_collector.replace(' ', '').replace('remotecollectorroleenabled=', '') == "true"):
            return('remote_collector')
        else:
            if(admin.replace(' ', '').replace('adminroleenabled=', '') == "false"):
                return('data_node')
            else:
                return('admin_node')
    def check_certsCMD(host_address):
        print(bcolors.BOLD + "--ROOT CERTIFICATE--" + bcolors.ENDC)
        print(subprocess_cmd("cat /storage/vcops/user/conf/ssl/web_chain.pem | openssl x509 -fingerprint -noout -dates", host_address))
        print(bcolors.BOLD + "--NODE CERTIFICATE--" + bcolors.ENDC)
        print(subprocess_cmd("cat /storage/vcops/user/conf/ssl/web_cert.pem | openssl x509 -fingerprint -noout -dates", host_address))


    def cluster_statusCMD(host_address):
        if (host.node_type(host_address) == 'remote_collector'):
            print("^^REMOTE COLLECTOR^^")
        else:
            if(host.node_type(host_address) == 'data_node'):
                print("^^DATA NODE^^")
                print(subprocess_cmd("$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status", host_address))
            else:
                print("^^ADMIN NODE^^")
                print(subprocess_cmd("$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status", host_address))


    def vROps_service_statusCMD(host_address):
        print(subprocess_cmd("/etc/init.d/vmware-vcops status", host_address))

def main(argv):
    switcher = {
        '-cl': local,
        '--check_local': local,
        '-ca': ssh_all,
        '--check_all': ssh_all,
        '-a': comm_allNodes,
        '--action': comm_allNodes,
        '-s': start,
        '--start_ssh': start,
        '-rs': removeOld,
        '--remove_ssh': removeOld,
        '-n': get_nodes_ID,
        '--node_ids': get_nodes_ID
    }
    errorMsg='options:\n -h, --help  show this options menu\n -a, --action <COMMAND>   run specified command on ALL nodes\n -ca, --check_all  brief health check on ALL nodes\n -rs, --remove_ssh  delete keys\n -s, --start   create and copy the key\n -n, --nodes   show nodes IDs\n'
    # Get the function from switcher dictionary
    func = switcher.get(argv[0], lambda: errorMsg)
    # Execute the function
    if len(argv) == 1:
        print(func())
    else:
        print(func(argv[1]))
    
def subprocess_cmd(command, host_address):
    if host_address == 'local':
        process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
        proc_stdout = process.communicate()[0].strip()
        output=proc_stdout.decode('ascii')
        return(output)
    else:
        process = subprocess.Popen("ssh root@{host} {cmd}".format(host=host_address, cmd=command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        proc_stdout = process.communicate()[0].strip()
        output=proc_stdout.decode('ascii')
        return(output)

def local():
    print(bcolors.OKCYAN + "▼▼▼" + socket.gethostname() + "▼▼▼" + bcolors.ENDC)
    commands=[host.dateCMD, 
              host.uptimeCMD, 
              host.hostnameCMD, 
              host.vROps_versionCMD, 
              host.ip_addressCMD,
              host.vm_sizingCMD,
              host.topCMD,
              host.storageCMD,
              host.local_OS_accountCMD,
              host.check_certsCMD,
              host.cluster_statusCMD,
              host.vROps_service_statusCMD]
    # BASIC INFO
    for comm, title in zip(commands,commandsTitle):
        print(bcolors.OKGREEN + "---" + title + "---" + bcolors.ENDC)
        comm('local')
        if comm == commands[-1]:
            pass
        else:
            os.system('read -s -n 1 -p "Press any key to continue..."')
            print()

def ssh_all():
    hosts=get_nodes_ID()
    commands=[host.dateCMD, 
              host.uptimeCMD, 
              host.hostnameCMD, 
              host.vROps_versionCMD, 
              host.ip_addressCMD,
              host.vm_sizingCMD,
              host.topCMD,
              host.storageCMD,
              host.local_OS_accountCMD,
              host.check_certsCMD,
              host.cluster_statusCMD,
              host.vROps_service_statusCMD]
    for comm, title in zip(commands,commandsTitle):
        print(bcolors.OKGREEN + "---" + title + "---" + bcolors.ENDC)
        for h in hosts:
            print(bcolors.OKCYAN + h + bcolors.ENDC)
            comm(h)
        if comm == commands[-1]:
            pass
        else:
            os.system('read -s -n 1 -p "Press any key to continue..."')
            print()

def comm_allNodes(comm):
    hosts=get_nodes_ID()
    for h in hosts:
        print(bcolors.OKCYAN + h + bcolors.ENDC)
        print(subprocess_cmd(comm, h))

def start():
    hosts=get_nodes_ID()
    subprocess.Popen("ssh-keygen",stdout=subprocess.PIPE, shell=True)
    for h in hosts:
        print(bcolors.OKCYAN + h + bcolors.ENDC)
        process = subprocess.Popen("ssh-copy-id -i /root/.ssh/id_rsa.pub {host}".format(host=h), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()[0]

def removeOld():
    hosts=get_nodes_ID()
    for h in hosts:
        subprocess.Popen("ssh-keygen -R {host}".format(host=h), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

def get_nodes_ID():
    grepped=subprocess_cmd("cat /storage/db/casa/webapp/hsqldb/casa.db.script | tr ',' '\n' | grep ip_address", 'local').splitlines()
    IDs=[]
    for ID in grepped:
        IDs.append(ID.replace('"ip_address":', '').replace('"', ''))   
    return(IDs)

if __name__ == "__main__":
   main(sys.argv[1:])