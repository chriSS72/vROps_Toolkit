#!/usr/lib/vmware-vcopssuite/python/bin/python

"""
Author:  Christian Soto (chsoto@vmware.com)
"""

##### BEGIN IMPORTS #####

import os
import subprocess
import socket
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='vROps Toolkit.')

    parser.add_argument('-a', '--action', type=str, help='run specified command on ALL nodes')
    parser.add_argument('-cl', '--check_local', action="store_true", help='brief health check on local node')
    parser.add_argument('-ca', '--check_all', action="store_true", help='brief health check on ALL nodes')
    parser.add_argument('-rs', '--remove_ssh', action="store_true", help='delete keys')
    parser.add_argument('-s', '--start', action="store_true", help='create and copy the key')
    parser.add_argument('-n', '--nodes', action="store_true", help='show nodes IDs')

    args = parser.parse_args()

    return(args)

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

def print_header(color, delim, title):
    print(f"{color}{delim}{title}{delim}{bcolors.ENDC}")

class host:
    def date_CMD(host_address):
        print(subprocess_cmd("date", host_address))

    def uptime_CMD(host_address):
        print(subprocess_cmd("uptime", host_address))

    def networking_CMD(host_address):
        print_header(bcolors.BOLD, "--", "HOSTNAME")
        print(subprocess_cmd("hostname -f", host_address))
        print_header(bcolors.BOLD, "--", "DNS SERVER(S)")
        print(subprocess_cmd("grep nameserver /etc/resolv.conf", host_address))
        print_header(bcolors.BOLD, "--", "GATEWAY")
        print(subprocess_cmd("ip r | grep default", host_address))
        print_header(bcolors.BOLD, "--", "IP ADDRESS")
        print(subprocess_cmd("ifconfig eth0", host_address))

    def vm_resources_CMD(host_address):
        print_header(bcolors.BOLD, "", "vCPUS:")
        
        num_of_vCPU=int(subprocess_cmd("nproc", host_address))
        print(num_of_vCPU)
        
        print_header(bcolors.BOLD, "", "RAM:")
        
        MemTotal_Conve=subprocess_cmd("grep 'MemTotal' /proc/meminfo", host_address)
        TotalRAM=host.conv_KB2GB(MemTotal_Conve)
        print("MemTotal:", TotalRAM, "GBs")
        MemFree_Conve=subprocess_cmd("grep 'MemFree' /proc/meminfo", host_address)
        print("MemFree:", host.conv_KB2GB(MemFree_Conve), "GBs")
        MemAvailable_Conve=subprocess_cmd("grep 'MemAvailable' /proc/meminfo", host_address)
        print("MemAvailable:", host.conv_KB2GB(MemAvailable_Conve), "GBs")
        SwapTotal_Conve=subprocess_cmd("grep 'SwapTotal' /proc/meminfo", host_address)
        print("SwapTotal:", host.conv_KB2GB(SwapTotal_Conve), "GBs")
        SwapFree_Conve=subprocess_cmd("grep 'SwapFree' /proc/meminfo", host_address)
        print("SwapFree:", host.conv_KB2GB(SwapFree_Conve), "GBs")

    def conv_KB2GB(strGrep):
        str_Conv=strGrep.split()
        GB_Conv=str(round(float(str_Conv[1])/1024**2, 2))
        return(GB_Conv) 
    
    def top_CMD(host_address):
        print(subprocess_cmd("top -n 1 -b | head -15", host_address))

    def vROps_version_CMD(host_address):
        print(subprocess_cmd("cat /usr/lib/vmware-vcops/user/conf/lastbuildversion.txt", host_address))

    def local_OS_account_CMD(host_address):
        print_header(bcolors.BOLD, "--", "ROOT ACCOUNT")
        print(subprocess_cmd("chage -l root", host_address))
        print(subprocess_cmd("pam_tally2 -u root", host_address))

        print_header(bcolors.BOLD, "--", "ADMIN ACCOUNT")
        print(subprocess_cmd("chage -l admin", host_address))
        print(subprocess_cmd("pam_tally2 -u admin", host_address))

        print_header(bcolors.BOLD, "--", "POSTGRES ACCOUNT")
        print(subprocess_cmd("chage -l postgres", host_address))
        print(subprocess_cmd("pam_tally2 -u postgres", host_address))

    def storage_CMD(host_address):
        print(subprocess_cmd("df -h", host_address))
        print_header(bcolors.WARNING , "--", "HEAPDUMPS")
        print(subprocess_cmd("ls -l /storage/db/vcops/heapdump/", host_address))

    def node_type(host_address):
        remote_collector=subprocess_cmd("grep remotecollectorroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties", host_address)
        admin=subprocess_cmd("grep -i adminroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties", host_address)
        if (remote_collector.replace(' ', '').replace('remotecollectorroleenabled=', '') == "true"):
            return('remote_collector')
        if(admin.replace(' ', '').replace('adminroleenabled=', '') == "false"):
            return('data_node')
        return('admin_node')

    def check_certs_CMD(host_address):
        keystore_pass=subprocess_cmd("cat /storage/vcops/user/conf/ssl/storePass.properties | grep sslkeystorePassword", host_address).split("=")[1]
        print("sslkeystorePassword =", keystore_pass)
        print(subprocess_cmd("keytool -v -list -keystore /storage/vcops/user/conf/ssl/tcserver.keystore -storepass {storepass}".format(storepass=keystore_pass), host_address))
        #print_header(bcolors.BOLD, "--", "ROOT CERTIFICATE")
        #print(subprocess_cmd("cat /storage/vcops/user/conf/ssl/web_chain.pem | openssl x509 -fingerprint -noout -dates", host_address))
        #print_header(bcolors.BOLD, "--", "NODE CERTIFICATE")
        #print(subprocess_cmd("cat /storage/vcops/user/conf/ssl/web_cert.pem | openssl x509 -fingerprint -noout -dates", host_address))

    def cluster_status_CMD(host_address):
        if (host.node_type(host_address) == 'remote_collector'):
            print_header(bcolors.BOLD, "^^", "REMOTE COLLECTOR")
        else:
            if(host.node_type(host_address) == 'data_node'):
                print_header(bcolors.BOLD, "^^", "DATA NODE")
                print(subprocess_cmd("$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status", host_address))
            else:
                print_header(bcolors.BOLD, "^^", "ADMIN NODE")
                print(subprocess_cmd("$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status", host_address))

    def vROps_service_status_CMD(host_address):
        print(subprocess_cmd("/etc/init.d/vmware-vcops status", host_address))

commandsTitle=["DATE",
        "UPTIME",
        "vROPS VERSION",
        "NETWORKING",
        "VM RESOURCES",
        "TOP",
        "STORAGE",
        "LOCAL OS ACCOUNTS",
        "CERTIFICATES",
        "CLUSTER STATUS",
        "VROPS SERVICES STATUS"]

commands=[host.date_CMD, 
        host.uptime_CMD, 
        host.vROps_version_CMD, 
        host.networking_CMD,
        host.vm_resources_CMD,
        host.top_CMD,
        host.storage_CMD,
        host.local_OS_account_CMD,
        host.check_certs_CMD,
        host.cluster_status_CMD,
        host.vROps_service_status_CMD]

def main():

    args = get_args()

    if args.action:
        comm_allNodes(args.action)
    elif args.check_local:
        local()
    elif args.check_all:
        ssh_all()
    elif args.start:
        start()
    elif args.remove_ssh:
        removeOld()
    elif args.nodes:
        print(get_nodes_ID())
    
def subprocess_cmd(command, host_address):
    if host_address == 'local':
        process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
    else:
        process = subprocess.Popen("ssh root@{host} {cmd}".format(host=host_address, cmd=command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    output=proc_stdout.decode('ascii')
    return(output)

def local():
    print_header(bcolors.OKCYAN, "▼▼▼", socket.gethostname())

    # BASIC INFO
    for comm, title in zip(commands,commandsTitle):
        print_header(bcolors.OKGREEN, "---", title)
        comm('local')
        if comm != commands[-1]:
            os.system('read -s -n 1 -p "Press any key to continue..."')
            print()

def ssh_all():
    hosts=get_nodes_ID()

    # BASIC INFO
    for comm, title in zip(commands,commandsTitle):
        print_header(bcolors.OKGREEN, "---", title)
        for h in hosts:
            print_header(bcolors.OKCYAN, "", h)
            comm(h)
        if comm != commands[-1]:
            os.system('read -s -n 1 -p "Press any key to continue..."')
            print()

def comm_allNodes(comm):
    hosts=get_nodes_ID()
    for h in hosts:
        print_header(bcolors.OKCYAN, '', h)
        print(subprocess_cmd(comm, h))

def start():
    hosts=get_nodes_ID()
    subprocess.Popen("ssh-keygen",stdout=subprocess.PIPE, shell=True)
    for h in hosts:
        print_header(bcolors.OKCYAN, "", h)
        process = subprocess.Popen("ssh-copy-id -i /root/.ssh/id_rsa.pub {host}".format(host=h), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()[0]

def removeOld():
    hosts=get_nodes_ID()
    for h in hosts:
        subprocess.Popen("ssh-keygen -R {host}".format(host=h), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

def get_nodes_ID():
    grepped=subprocess_cmd("cat /storage/db/casa/webapp/hsqldb/casa.db.script | tr ',' '\n' | grep ip_address", 'local').splitlines()
    return [ID.split('"')[3] for ID in grepped]

if __name__ == "__main__":
    main()