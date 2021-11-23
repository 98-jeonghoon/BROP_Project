#!/bin/sh
while true; do
    num=`ps -ef | grep "10002" | grep -v "grep" | wc -l`
    if [ $num -eq 0 ]; then
        socat tcp4-listen:10002,reuseaddr,fork exec:./test &
    fi
done
