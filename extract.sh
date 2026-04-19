#!/bin/bash

sed -e '/CPU Time\|Sending request to server/,/Enc/!d' $1 | grep -E "(Encrypting|CPU Time)" | cut -d" " -f 2,8 | tr -d '['
