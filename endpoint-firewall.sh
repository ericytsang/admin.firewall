# !/bin/sh

# this script is meant to set up firewalls for endpoint nodes on a network

### code - do not modify ###

# general
IPT="iptables"
PS4='$LINENO '

# ports
ALL_PORTS="0:65535"
UNPRIV_PORTS="1025:65535"
PRIV_PORTS="0:1024"

# addresses
BROADCAST_SRC_ADDR="0.0.0.0/32"
BROADCAST_DEST_ADDR="255.255.255.255/32"

### TCP/UDP configuration - ok to modify ###

# network interfaces
WAN_NIC="enp0s25"
LAN_NIC="enp0s25"
LO_NIC="lo"

# host addresses
WAN_ADDR="192.168.1.3/32"
LAN_ADDR="192.168.1.0/24"
LO_ADDR="127.0.0.1/32"
ANY_ADDR="0.0.0.0/0"
GATEWAY_ADDR="192.168.1.1"

# syntax: "network_interface,local_ip,subnet_ip,dhcp_server_ip network_interface,local_ip,subnet_ip,dhcp_server_ip..."
DHCP_SERVERS="\
${WAN_NIC},${WAN_ADDR},${LAN_ADDR},${GATEWAY_ADDR}\
"

# syntax: "network_interface,local_ip,local_port,remote_ip,remote_port network_interface,local_ip,local_port,remote_ip,remote_port"
# example: "tcp,0.0.0.0/0,22 udp,192.168.1.72/32,53"
LOCAL_TCP_SERVERS="\
${WAN_NIC},${WAN_ADDR},56322,${ANY_ADDR},${UNPRIV_PORTS} \
${LO_NIC},${LO_ADDR},56322,${ANY_ADDR},${UNPRIV_PORTS} \
${WAN_NIC},${WAN_ADDR},56311:56321,${ANY_ADDR},${UNPRIV_PORTS} \
${LO_NIC},${LO_ADDR},56311:56321,${ANY_ADDR},${UNPRIV_PORTS} \
${WAN_NIC},${WAN_ADDR},3306,${ANY_ADDR},${UNPRIV_PORTS} \
${LO_NIC},${LO_ADDR},3306,${ANY_ADDR},${UNPRIV_PORTS} \
${WAN_NIC},${WAN_ADDR},58080,${ANY_ADDR},${UNPRIV_PORTS} \
${LO_NIC},${LO_ADDR},58080,${ANY_ADDR},${UNPRIV_PORTS}\
"
LOCAL_UDP_SERVERS="\
"
REMOTE_TCP_SERVERS="\
${WAN_NIC},${WAN_ADDR},${UNPRIV_PORTS},${ANY_ADDR},${ALL_PORTS}\
"
REMOTE_UDP_SERVERS="\
${WAN_NIC},${WAN_ADDR},${UNPRIV_PORTS},${ANY_ADDR},${ALL_PORTS}\
"

# allowed ICMP packet types
# syntax: "network_interface,local_ip,remote_ip,icmp_type"
INBOUND_ICMP_TYPES="${WAN_NIC},${WAN_ADDR},${ANY_ADDR},0"
OUTBOUND_ICMP_TYPES="${WAN_NIC},${WAN_ADDR},${ANY_ADDR},8"

### code - do not modify ###

# reset firewall
$IPT -F
$IPT -X
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT

if [ "$1" = "stop" ]
then
    echo "Firewall cleared"
    exit 0
fi

# set default chain policies
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# create user chains
USER_CHAINS="DHCP DNS ICMP TCP_SVR TCP_CLNT UDP_SVR UDP_CLNT"
for CHAIN in $USER_CHAINS
do
    $IPT -N $CHAIN
    $IPT -A $CHAIN -j ACCEPT
done

# enable DHCP traffic to DHCP servers
for PARAMS in $DHCP_SERVERS
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    SUBNET_ADDR=$3
    DHCP_SERVER_ADDR=$4

    # make firewall rules
    $IPT -A OUTPUT -o $NIC -p udp \
                -s $BROADCAST_SRC_ADDR --sport 67:68 \
                -d $BROADCAST_DEST_ADDR --dport 67:68 \
                -j DHCP
    $IPT -A INPUT -i $NIC -p udp \
                -s $DHCP_SERVER_ADDR --sport 67 \
                -d $SUBNET_ADDR --dport 68 \
                -j DHCP
    $IPT -A OUTPUT -o $NIC -p udp \
                -d $DHCP_SERVER_ADDR --dport 67 \
                -s $LOCAL_ADDR --sport 68 \
                -j DHCP
    $IPT -A INPUT -i $NIC -p udp \
                -s $DHCP_SERVER_ADDR --sport 67 \
                -d $LOCAL_ADDR --dport 68 \
                -j DHCP
done

# enable inbound ICMP traffic based on type
for PARAMS in $INBOUND_ICMP_TYPES
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    REMOTE_ADDR=$3
    ICMP_TYPE=$4

    # make firewall rules
    $IPT -A INPUT -i $NIC -p icmp --icmp-type $ICMP_TYPE \
                -s $REMOTE_ADDR \
                -d $LOCAL_ADDR \
                -j ICMP
done

# enable outbound ICMP traffic based on type
for PARAMS in $OUTBOUND_ICMP_TYPES
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    REMOTE_ADDR=$3
    ICMP_TYPE=$4

    # make firewall rules
    $IPT -A OUTPUT -o $NIC -p icmp --icmp-type $ICMP_TYPE \
                -s $LOCAL_ADDR \
                -d $REMOTE_ADDR \
                -j ICMP
done

# enable access to local TCP servers from network
for PARAMS in $LOCAL_TCP_SERVERS
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    LOCAL_PORT=$3
    REMOTE_ADDR=$4
    REMOTE_PORT=$5

    # make firewall rules
    $IPT -A INPUT -i $NIC -p tcp \
        -s $REMOTE_ADDR --sport $REMOTE_PORT \
        -d $LOCAL_ADDR --dport $LOCAL_PORT \
        -m state --state NEW,ESTABLISHED --tcp-flags NONE NONE -j TCP_SVR
    $IPT -A OUTPUT -o $NIC -p tcp \
        -s $LOCAL_ADDR --sport $LOCAL_PORT \
        -d $REMOTE_ADDR --dport $REMOTE_PORT \
        -m state --state ESTABLISHED --tcp-flags ACK  ACK -j TCP_SVR
done

# enable outbound TCP traffic to remote TCP servers
for PARAMS in $REMOTE_TCP_SERVERS
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    LOCAL_PORT=$3
    REMOTE_ADDR=$4
    REMOTE_PORT=$5

    # make firewall rules
    $IPT -A INPUT -i $NIC -p tcp \
        -s $REMOTE_ADDR --sport $REMOTE_PORT \
        -d $LOCAL_ADDR --dport $LOCAL_PORT \
        -m state --state ESTABLISHED -j TCP_CLNT
    $IPT -A OUTPUT -o $NIC -p tcp \
        -s $LOCAL_ADDR --sport $LOCAL_PORT \
        -d $REMOTE_ADDR --dport $REMOTE_PORT \
        -m state --state NEW,ESTABLISHED -j TCP_CLNT
done

# enable access to local UDP servers from network
for PARAMS in $LOCAL_UDP_SERVERS
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    LOCAL_PORT=$3
    REMOTE_ADDR=$4
    REMOTE_PORT=$5

    # make firewall rules
    $IPT -A OUTPUT -o $NIC -p udp \
        -s $LOCAL_ADDR --sport $LOCAL_PORT \
        -d $REMOTE_ADDR --dport $REMOTE_PORT \
        -j UDP_SVR
    $IPT -A INPUT -i $NIC -p udp \
        -s $REMOTE_ADDR --sport $REMOTE_PORT \
        -d $LOCAL_ADDR --dport $LOCAL_PORT \
        -j UDP_SVR
done

# enable outbound UDP traffic to remote UDP servers
for PARAMS in $REMOTE_UDP_SERVERS
do
    # parse parameters
    IFS=","
    set $PARAMS
    IFS=" "
    NIC=$1
    LOCAL_ADDR=$2
    LOCAL_PORT=$3
    REMOTE_ADDR=$4
    REMOTE_PORT=$5

    # make firewall rules
    $IPT -A OUTPUT -o $NIC -p udp \
        -s $LOCAL_ADDR --sport $LOCAL_PORT \
        -d $REMOTE_ADDR --dport $REMOTE_PORT \
        -j UDP_CLNT
    $IPT -A INPUT -i $NIC -p udp \
        -s $REMOTE_ADDR --sport $REMOTE_PORT \
        -d $LOCAL_ADDR --dport $LOCAL_PORT \
        -j UDP_CLNT
done

