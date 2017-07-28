#!/bin/bash

ls -1 $1/ | \
    while read line; do
	echo "  $1/$line"
    done
