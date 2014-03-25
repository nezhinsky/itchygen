#!/bin/bash

if [[ $# < 3 ]]; then
	echo "usage: $0 [subscription_file] [num_entries:=1000] [out_file]"
	exit 1;
fi

fname=$1
num_entries=$2
out_file=$3

cat ${fname} | sort --random-sort | head -n ${num_entries} > $3

