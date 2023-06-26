#!/bin/bash

process_name="dauth_api"
pid_file="./$process_name.pid"

start() {
    echo "Starting $process_name..."
    daemon_cmd="./app"
    $daemon_cmd & 
    echo $! > $pid_file
}

stop() {
    if [ -f $pid_file ]; then
        pid=$(cat $pid_file)
        echo "Stopping $process_name with PID $pid..."
        kill $pid
        rm $pid_file
    else
        echo "$process_name is not running"
    fi
}

status() {
    if [ -f $pid_file ]; then
        pid=$(cat $pid_file)
        if ps -p $pid > /dev/null; then
            echo "$process_name is running with PID $pid"
            exit 0
        else
            echo "$process_name PID file exists but process is not running"
            rm $pid_file
            exit 1
        fi
    else
        echo "$process_name is not running"
        exit 1
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac

exit 0
