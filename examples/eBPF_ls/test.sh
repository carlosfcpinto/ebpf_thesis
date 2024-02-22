#!/bin/bash
#

touch this

if chmod +x this; then
	echo "Operation allowed"
	exit 0
else 
	echo "Operation not allowed"
	exit 1
fi
