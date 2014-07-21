#################
#     Ip's      #
#################
ip1=$1
ip2=$2
ip3=$3
ip4=$4
#################
#     Stuff     #
#################
threads=$5
list=$6
domain=$7
timeout=$8 ## fasttttt


[ $# -eq 0 ] && { echo "Usage: $0 90 0 0-255 0-255 threads list domain timeout"; exit 1; }
[ $# -eq 1 ] && { echo "Forgot Ip range"; exit 1; }
[ $# -eq 2 ] && { echo "Forgot Ip range"; exit 1; }
[ $# -eq 3 ] && { echo "Forgot Ip range"; exit 1; }
[ $# -eq 4 ] && { echo "Forgot threads"; exit 1; }
[ $# -eq 5 ] && { echo "Forgot output list :/"; exit 1; }
[ $# -eq 6 ] && { echo "Forgot domain.. idiot"; exit 1; }
[ $# -eq 7 ] && { echo "Timeout bro... timeout...."; exit 1; }


nmap $ip1.$ip2.$ip3.$ip4 --script=dns-recursion -sU -p53 --min-parallelism $threads -oG - -host_timeout $8 | grep "53/open/udp//domain///" > tmpd
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' tmpd > tmpd2
sed "s/$/ $domain/g" tmpd2 > tmpd3
cp tmpd3 $list
rm -rf tmpd*
killall -9 nmap
echo "Saved as $list"
