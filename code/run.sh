#!/bin/sh
while true; do
    num=`ps -ef | grep "10001" | grep -v "grep" | wc -l`
    if [ $num -eq 0 ]; then
        socat tcp4-listen:10001,reuseaddr,fork exec:./brop &
    fi
done
