#!/bin/bash

# This script calls the Python script `classifyFlows.py' on all pcap files
# in the given input directory to generate features.


dir="$1"
pred_flag=False
array=(Browser Fruit News Weather Youtube)


for label in ${array[@]}
do
    for f in "$dir"/"$label"/*.pcap
    do
        python3 classifyFlows.py $f $pred_flag
    done
done


