# oswe-scripts
for my personal use. so it may not be so user friendly or it may not even work at all! 

## for xss-webfuzzer.py

a simple XSS web fuzzer that can takes payloads from http://htmlpurifier.org/live/smoketests/xssAttacks.xml

------
[how]

POST REQUEST 
python3 xss-web-fuzzer.py -m GET -d 'field1=PAYPAY&field2=test' -u http://test.com -px 127.0.0.1:8080

GET REQUEST
python3 xss-web-fuzzer.py -m POST -d 'field1=PAYPAY&field2=test' -u http://test.com -px 127.0.0.1:8080

USAGE HELP INFORMATION
python3 xss-web-fuzzer.py --help                                                                                                                                                 
usage: xss-web-fuzzer.py [-h] -m METHOD -d DATA -u URL [-L] [-r REPLAY] [-px PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -m METHOD, --method METHOD
                        Method to use: GET or POST
  -d DATA, --data DATA  The entire payload with the fields to send with PAYPAY inside the field (eg. "field1=PAYPAY&field2=hi")
  -u URL, --url URL     URL / Target link
  -L, --listmode        Load XML file and show available XSS payloads
  -r REPLAY, --replay REPLAY
                        Send a payload number / Replay payload number from list
  -px PROXY, --proxy PROXY
                        Enable proxy; in this format: 127.0.0.1:8080

------

