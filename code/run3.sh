#!/bin/sh
while true; do
    num=`ps -ef | grep "10003" | grep -v "grep" | wc -l`
    if [ $num -eq 0 ]; then
        socat tcp4-listen:10003,reuseaddr,fork exec:./test2 &
    fi
done
