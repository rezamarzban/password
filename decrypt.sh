#!/bin/bash

key=$(echo -n "YOUR_KEY" | xxd -p | tr -d '\n')

echo -n "YOUR_HEX_STRING" | xxd -r -p | openssl enc -aes-256-ecb -d -K "$key" -nopad
