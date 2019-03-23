#!bin/bash

ab -p post_b.txt -T application/json -H 'Token ed973a2699ef67d666c3cec922afe6f9df783773' -c 10 -n 10 https://127.0.0.1/accounts/get_credential > results.txt