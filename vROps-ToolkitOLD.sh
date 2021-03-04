#/bin/bash
#
casaDBscript="/storage/db/casa/webapp/hsqldb/casa.db.script";
nodeID=$(cat $casaDBscript | tr ',' '\n' | grep ip_address | awk 'BEGIN { FS = ":" } ; { print $2 }' | cut -c 2- | rev | cut -c 2- | rev);
printf '%s\n' "${nodeID[@]}" > /tmp/nodes.txt;
nodeRole=$(cat $casaDBscript | tr ',' '\n' | grep 'slice_name' | awk 'BEGIN { FS = ":" } ; { print $2 }' | cut -c 2- | rev | cut -c 2- | rev);
printf '%s\n' "${nodeRole[@]}" > /tmp/roles.txt;
#
#function heap_dump {
#       if [ $(ls /storage/heapdump/*.hprof | wc -l) != 0 ]
#       then
#               echo -e '\e[0;33m--HEAPDUMPS--\e[0m'
#               ls -l /storage/heapdump/*.hprof;
#       fi
#}
#
#if [$(ls /storage/heapdump/ | grep hprof | wc -l) -gt 0 ]; then echo -e '\e[0;33m--HEAPDUMPS--\e[0m'; ls -l /storage/heapdump/*.hprof; fi"
#
CommandsTitle=("DATE"
        "UPTIME"
        "HOSTNAME"
        "VCPUS AND RAM"
        "TOP"
        "IP ADDRESS(ES)"
        "vROPS VERSION"
        "LOCAL OS ACCOUNTS"
        "STORAGE"
        "CLUSTER STATUS"
        "VROPS SERVICES STATUS");
Commands=("date"
        "uptime"
        "hostname -f"
        "echo -e 'vCPUS:'; grep -wc processor /proc/cpuinfo; echo -e 'RAM:'; grep 'MemTotal\|MemFree\|MemAvailable\|SwapTotal\|SwapFree' /proc/meminfo"
        "top -n 1 -b | head -15"
        "ifconfig eth0"
        "rpm -qa | grep --color=never -i 'vmware-vcops-[0-9]'"
        "echo -e '---ROOT ACCOUNT---'; chage -l root; pam_tally2 -u root;
        echo -e '---ADMIN ACCOUNT---'; chage -l admin; pam_tally2 -u admin;
        echo -e '---POSTGRES ACCOUNT---'; chage -l postgres; pam_tally2 -u postgres"
        "df -h; echo -e '\e[0;33m--HEAPDUMPS--\e[0m'; ls -l /storage/heapdump/"
        "$VCOPS_BASE/cassandra/apache-cassandra-*/bin/nodetool -p 9008 --ssl -u maintenanceAdmin --password-file /usr/lib/vmware-vcops/user/conf/jmxremote.password status"
        "/etc/init.d/vmware-vcops status");
#
if [ -z "$1" ]
then
        echo "Try '$0 --help'";
        exit 1
fi
#
while test $# -gt 0; do
  case "$1" in
    -h|--help)
                echo " ";
                echo "$0 [option] '[argument]'";
                echo " ";
                echo "options:";
                echo "-h, --help                show this options menu";
                echo "-a, --action 'COMMAND'    run specified command on ALL nodes";
                echo "-c, --check               brief health check on ALL nodes";
                echo "-ro, --removeOld          delete keys";
                echo "-s, --start               create and copy the key";
                echo "-n, --nodes               show nodes IDs";
                exit 0
        ;;
        -n|--nodes)
        echo -e "\e[1;32mVROPS NODES FQDN/IP\e[0m";
        cat /tmp/nodes.txt;
        exit 0
        ;;
    -s|--start)
                ssh-keygen;
                for i in $(cat /tmp/nodes.txt); do
                        echo  -e "\e[1;32m$i\e[0m";
                        ssh-copy-id -i /root/.ssh/id_rsa.pub root@$i;
                done
                exit 0
        ;;
    -ro|--removeOld)
                ssh-keygen -R $HOSTNAME;
                exit 0
        ;;
    -c|--check)
                for j in ${!CommandsTitle[*]}; do
                        echo -e "\e[1;32m----${CommandsTitle[$j]}----\e[0m"
                        for i in $(cat /tmp/nodes.txt); do
                                echo  -e "\e[1;36m$i\e[0m";
                                ssh -q root@$i ${Commands[$j]};
                                echo "";
                        done
                        if [ $[ $j + 1 ] != ${#CommandsTitle[@]} ]
                        then
                                read -p "Press ENTER to continue";
                        fi
                done
                exit 0
        ;;
    -a|--action)
                shift
                comm=$1
                for i in $(cat /tmp/nodes.txt); do
                        echo  -e "\e[1;32m$i\e[0m";
                        ssh -q root@$i $comm;
                        echo "";
                done
                exit 0
        ;;
    *)
                echo "invalid flag '$1'";
                echo "Valid options are:";
                echo "  - 'start'";
                echo "  - 'check'";
                echo "  - 'action'";
                echo "Usage: ./ssh-all.sh [OPTION]...";
                echo "Try './ssh-all.sh --help' for more information.";
        break
        ;;
    esac
done