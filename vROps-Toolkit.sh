#/bin/bash

:<<'###########################################'
Author:  Christian Soto (chsoto@vmware.com)
###########################################

declare -A bcolors;

bcolors[HEADER]="\033[95m";
bcolors[OKBLUE]="\033[94m";
bcolors[OKCYAN]="\033[96m";
bcolors[OKGREEN]="\033[92m";
bcolors[WARNING]="\033[93m";
bcolors[FAIL]="\033[91m";
bcolors[ENDC]="\033[0m";
bcolors[BOLD]="\033[1m";
bcolors[UNDERLINE]="\033[4m";

print_header() {
    echo -e "$1$2$3$2${bcolors[ENDC]}";
}

date_CMD() { subprocess_cmd "date -u" $1;}
uptime_CMD() { subprocess_cmd "uptime" $1;}
networking_CMD() {
    print_header ${bcolors[BOLD]} "--" "HOSTNAME"; subprocess_cmd "hostname -f" $1;
    print_header ${bcolors[BOLD]} "--" "DNS SERVER(S)"; subprocess_cmd "grep nameserver /etc/resolv.conf" $1;
    print_header ${bcolors[BOLD]} "--" "GATEWAY"; subprocess_cmd "ip r | grep default" $1;
    print_header ${bcolors[BOLD]} "--" "IP ADDRESS"; subprocess_cmd "ifconfig eth0" $1;
}
vm_resources_CMD() {
    print_header ${bcolors[BOLD]} "" "vCPUS:"; subprocess_cmd "nproc" $1;
    print_header ${bcolors[BOLD]} "" "RAM:";
    subprocess_cmd "grep 'MemTotal\|MemFree\|MemAvailable\|SwapTotal\|SwapFree' /proc/meminfo" $1;
    #awk '$3=="kB"{$2=$2/1024**2;$3="GB";} 1' /proc/meminfo | column -t | grep MemTotal;
    #awk '$3=="kB"{$2=$2/1024**2;$3="GB";} 1' /proc/meminfo | column -t | grep MemFree;
    #awk '$3=="kB"{$2=$2/1024**2;$3="GB";} 1' /proc/meminfo | column -t | grep MemAvailable;
    #awk '$3=="kB"{$2=$2/1024**2;$3="GB";} 1' /proc/meminfo | column -t | grep SwapTotal;
    #awk '$3=="kB"{$2=$2/1024**2;$3="GB";} 1' /proc/meminfo | column -t | grep SwapTotal;
}
top_CMD() { 
    subprocess_cmd "top -n 1 -b" $1;
}
vROps_version_CMD() { subprocess_cmd "cat /usr/lib/vmware-vcops/user/conf/lastbuildversion.txt" $1;}
local_OS_account_CMD() {
    print_header ${bcolors[BOLD]} "--" "ROOT ACCOUNT"; subprocess_cmd "chage -l root" $1; subprocess_cmd "pam_tally2 -u root" $1;
    print_header ${bcolors[BOLD]} "--" "ADMIN ACCOUNT"; subprocess_cmd "chage -l admin" $1; subprocess_cmd "pam_tally2 -u admin" $1;
    print_header ${bcolors[BOLD]} "--" "POSTGRES ACCOUNT"; subprocess_cmd "chage -l postgres" $1; subprocess_cmd "pam_tally2 -u postgres" $1;
}
storage_CMD() {
    subprocess_cmd "df -h" $1;
    print_header ${bcolors[WARNING]} "--" "HEAPDUMPS";
    subprocess_cmd "ls -l /storage/db/vcops/heapdump/" $1;
}
node_type() {
    remote_collector_init=$(subprocess_cmd "grep remotecollectorroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties" $1);
    remote_collector=$(echo $remote_collector_init | awk '{ print $NF }');
    admin_init=$(subprocess_cmd "grep -i adminroleenabled /usr/lib/vmware-vcopssuite/utilities/sliceConfiguration/data/roleState.properties" $1);
    admin=$(echo $admin_init | awk '{ print $NF }');
}
check_certs_CMD() {
    keystore_pass=$(grep sslkeystorePassword /storage/vcops/user/conf/ssl/storePass.properties | awk 'BEGIN { FS = "=" } ; { print $NF }');
    echo "sslkeystorePassword = $keystore_pass";
    keytool -v -list -keystore /storage/vcops/user/conf/ssl/tcserver.keystore -storepass $keystore_pass;
}
cluster_status_CMD() {
    node_type $1;
    if [ "$admin" = "true" ]
    then
        print_header ${bcolors[HEADER]} "^" "ADMIN NODE";
        subprocess_cmd "$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status" $1;
    elif [ "$remote_collector" = "true" ]
    then
        print_header ${bcolors[FAIL]} "^" "REMOTE COLLECTOR NODE";
    else
        print_header ${bcolors[HEADER]} "^" "DATA NODE";
        subprocess_cmd "$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status" $1;
    fi
    
}
vROps_service_status_CMD() { subprocess_cmd "/etc/init.d/vmware-vcops status" $1;}

casaDBscript="/storage/db/casa/webapp/hsqldb/casa.db.script";

CommandsTitle=("DATE" "UPTIME" "vROPS_VERSION" "NETWORKING" "VM_RESOURCES" "TOP" "STORAGE"
            "LOCAL_OS_ACCOUNTS" "CERTIFICATES" "CLUSTER_STATUS" "VROPS_SERVICES_STATUS");

commands=(date_CMD uptime_CMD vROps_version_CMD networking_CMD vm_resources_CMD top_CMD storage_CMD
            local_OS_account_CMD check_certs_CMD cluster_status_CMD vROps_service_status_CMD);

get_nodes_ID() {        
    nodeID=$(cat $casaDBscript | tr ',' '\n' | grep ip_address | awk 'BEGIN { FS = ":" } ; { print $2 }' | cut -c 2- | rev | cut -c 2- | rev);
    nodeRole=$(cat $casaDBscript | tr ',' '\n' | grep 'slice_name' | awk 'BEGIN { FS = ":" } ; { print $2 }' | cut -c 2- | rev | cut -c 2- | rev);
    nodeNum=$(cat /storage/db/casa/webapp/hsqldb/casa.db.script | tr ',' '\n' | grep ip_address | wc -l);
    printf '%s\n' "${nodeID[@]}" > /tmp/nodes.txt;
    printf '%s\n' "${nodeRole[@]}" > /tmp/.roles.txt;

    IFS=$'\n' read -d '' -r -a nodeIDarray < /tmp/nodes.txt;
    IFS=$'\n' read -d '' -r -a nodeROLEarray < /tmp/.roles.txt;

    rm /tmp/.roles.txt;
}

subprocess_cmd() {
    if [ "$2" = "local" ]
    then
        $1;
    else
        ssh -q root@$2 $1;
    fi
}

local() {
    print_header ${bcolors[OKCYAN]} "▼▼▼" $HOSTNAME;

    # BASIC INFO
    for j in ${!commands[*]}; do
        print_header ${bcolors[OKGREEN]} "---" ${CommandsTitle[$j]};
        ${commands[$j]} "local";
        echo "";
        if [ $[ $j + 1 ] != ${#commands[@]} ]
        then
            read -s -n 1 -p "Press any key to continue...";
            echo "";
        fi
    done
}

ssh_all() {
    get_nodes_ID;
    
    # BASIC INFO
    for j in ${!commands[*]}; do
        print_header ${bcolors[OKGREEN]} "---" ${CommandsTitle[$j]};
        for i in "${nodeIDarray[@]}"; do
            print_header ${bcolors[OKCYAN]} "" $i;
            ${commands[$j]} $i;
            echo "";
        done
        if [ $[ $j + 1 ] != ${#CommandsTitle[@]} ]
        then
            read -s -n 1 -p "Press any key to continue...";
            echo "";
        fi
    done
}

scp_files() {
    get_nodes_ID;

    for i in "${nodeIDarray[@]}"; do
        print_header ${bcolors[OKCYAN]} "" $i;
        scp -r $1 $i:$2;
        echo "";
    done
}

comm_allNodes() {
    get_nodes_ID;

    for i in "${nodeIDarray[@]}"; do
        print_header ${bcolors[OKCYAN]} "" $i;
        subprocess_cmd $1 $i;
    done
}

if [ -z "$1" ]
then
    echo "Try '$0 --help' or '$0 -h'";
    exit 1
fi

while test $# -gt 0; do
    case "$1" in
        -h|--help)
            echo " ";
            echo "$0 [option] '[argument]'";
            echo " ";
            echo "options:";
            echo "-h, --help                        show this options menu";
            echo "-a, --action \"<COMMAND>\"        run specified command on ALL nodes";
            echo "-cl, --check_local                brief health check on local node";
            echo "-ca, --check_all                  brief health check on ALL nodes";
            echo "-rs, --remove_ssh                 delete keys";
            echo "-n, --nodes                       show nodes IDs";
            echo "-a -p \"<PASSWORD>\" \"<COMMAND>\", \n--action -password \"<PASSWORD>\" \"<COMMAND>\"     run specified command on ALL nodes using root password instead of SSH Keys";
            echo "-s -p \"<PASSWORD>\", \n--start -password \"<PASSWORD>\"                                  create and copy the key";
            exit 0
            ;;
        -n|--nodes)
            print_header ${bcolors[OKGREEN]} "" "VROPS NODES FQDN/IP";
            get_nodes_ID;

            for ((node=0;node<=$[$nodeNum-1];node++)); do
                printf "%s (%s)\n" "${nodeIDarray[node]}" "${nodeROLEarray[node]}";
            done
            exit 0
            ;;
        -s|--start)
            print_header ${bcolors[OKGREEN]} "" "GETTING SSH KEYS";
            get_nodes_ID;
            ssh-keygen;
            case "$2" in
                -p|--password)
                    pass=$3
                    echo -e "Trying with password: $pass";
                    for i in "${nodeIDarray[@]}"; do
                        print_header ${bcolors[OKCYAN]} "" $i;
                        sshpass -p $pass ssh-copy-id -i /root/.ssh/id_rsa.pub root@$i;
                    done
                    ;;
                *)
                    for i in "${nodeIDarray[@]}"; do
                        print_header ${bcolors[OKCYAN]} "" $i;
                        ssh-copy-id -i /root/.ssh/id_rsa.pub root@$i;
                    done
                    break
                    ;;
            esac
            exit 0
            ;;
        -rs|--remove_ssh)
            print_header ${bcolors[OKGREEN]} "" "DELETING SSH KEYS";
            get_nodes_ID;
            for i in "${nodeIDarray[@]}"; do
                ssh-keygen -R $i;
            done
            echo "DONE";
            exit 0
            ;;
        -ca|--check_all)
            get_nodes_ID;
            ssh_all;
            exit 0
            ;;
        -cl|--check_local)
            local;
            exit 0
            ;;
        -a|--action)
            get_nodes_ID;
            case "$2" in
                -p|--password)
                    comm=$4;
                    pass=$3
                    echo -e "Trying with password: $pass";
                    for i in "${nodeIDarray[@]}"; do
                        echo  -e "\e[1;32m$i\e[0m";
                        SSHPASS='$pass' sshpass -e ssh -o StrictHostKeyChecking=no -q root@$i $comm;
                        echo "";
                    done
                    ;;
                *)
                    comm=$2;
                    for i in "${nodeIDarray[@]}"; do
                        echo  -e "\e[1;32m$i\e[0m";
                        ssh -q root@$i $comm;
                        echo "";
                    done
                    break
                    ;;
            esac
            exit 0
            ;;
        *)
            echo "invalid flag '$1'";
            echo "Valid options are:";
            echo "-h, --help                        show this options menu";
            echo "-a, --action \"<COMMAND>\"        run specified command on ALL nodes";
            echo "-cl, --check_local                brief health check on local node";
            echo "-ca, --check_all                  brief health check on ALL nodes";
            echo "-rs, --remove_ssh                 delete keys";
            echo "-n, --nodes                       show nodes IDs";
            echo "-a -p \"<PASSWORD>\" \"<COMMAND>\", \n--action -password \"<PASSWORD>\" \"<COMMAND>\"     run specified command on ALL nodes using root password instead of SSH Keys";
            echo "-s -p \"<PASSWORD>\", \n--start -password \"<PASSWORD>\"                                  create and copy the key";
            echo "Usage: $0 [OPTION]...";
            echo "Try '$0 --help' for more information.";
            break
            ;;
    esac
done