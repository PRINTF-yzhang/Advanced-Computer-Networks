#!/bin/bash

# This script calls the Python script `classifyFlows.py' on all pcap files
# in the given input directory to pred labels

# Usage:
#   ./pred.sh dir
#

dir="$1"
pred_flag=True

for f in "$dir"/*.pcap
do
    python3 classifyFlows.py $f $pred_flag
done

