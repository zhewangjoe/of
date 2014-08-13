#!/bin/bash

IFTMPFILE=`mktemp`

SWITCHNAME="br-switch"
RETRYCOUNT=0
IFLIST=""

while [ $RETRYCOUNT -lt 30 ]; do

    # Get the list of interfaces (filtering out OVS bridges and loopback)
    ifconfig -a | grep "Link encap" | grep -v ^lo | grep -v ^br | awk '{print $1, $5}' > $IFTMPFILE

    echo "=== $RETRYCOUNT ===" >> /tmp/geniovs
    cat $IFTMPFILE >> /tmp/geniovs
    
    CONTROLMAC=`/usr/bin/geni-get control_mac`
    CONTROLNAME=""

    # Pull the control interface out of the list
    while read if; do
        IFNAME=`echo $if | awk '{print $1}'` 
        IFMAC=`echo $if | awk '{print $2}' | sed -e 's/://g'`
        if [ "$IFMAC" == "$CONTROLMAC" ]; then
            CONTROLNAME=$IFNAME
        else
            IFLIST="$IFLIST $IFNAME"
        fi
    done < $IFTMPFILE

    # If we didn't find the control interface, we have a problem.  Bail.
    if [ "$CONTROLNAME" == "" ]; then
        echo "Control interface with MAC $CONTROLMAC not found"
        rm -f $IFTMPFILE
        exit 1
    fi

    # Create the switch if it doesn't already exist
    sudo ovs-vsctl list-br | grep -q $SWITCHNAME 
    if [ $? -ne 0 ]; then
        sudo ovs-vsctl add-br $SWITCHNAME
        sudo ovs-vsctl set-fail-mode $SWITCHNAME secure 
    fi

    # Create ports for each of the interfaces if they don't exist
    # and clear the IP address
    for i in $IFLIST; do
        sudo ovs-vsctl list-ports $SWITCHNAME | grep -q ${i}
        if [ $? -ne 0 ]; then
            sudo ovs-vsctl add-port $SWITCHNAME ${i}
            sudo ifconfig ${i} 0.0.0.0
        fi
    done

    RETRYCOUNT=$(( $RETRYCOUNT + 1 ))
    sleep 10

done

rm -f $IFTMPFILE
