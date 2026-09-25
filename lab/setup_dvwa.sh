#!/bin/bash
# Setup DVWA database
curl -s -c /tmp/cookies.txt http://localhost/login.php > /dev/null
TOKEN=$(curl -s -b /tmp/cookies.txt http://localhost/setup.php | grep -oP "value='[^']+'" | head -1 | cut -d"'" -f2)
echo "Token: $TOKEN"
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -X POST http://localhost/setup.php \
  -d "create_db=Create+/-+Reset+Database&user_token=$TOKEN" > /tmp/setup_result.html
grep -oiP "(Database has been created|Could not create|error|Success|Failed|tables)[^<]{0,200}" /tmp/setup_result.html | head -10
echo "---"
# Verify SQLi page has forms
curl -s -b /tmp/cookies.txt http://localhost/vulnerabilities/sqli/ | grep -c "<form"
