# CSRF-Example
This repo is the code from Become An Ethical Hacker, Attacking Webapps. CSRF, or Cross Site Request Forgery example which is an attack that relies on a user already being authenticated to an application.

# Prequisites
Create an SSL cert.

kali@kali:$ cd go/src/csrfapp
kali@kali:/go/src/csrfapp$ openssl req -newkey rsa:4096 \
            -x509 \
            -sha256 \
            -days 3650 \
            -nodes \
            -out csrfapp.crt \
            -keyout csrfapp.key


# Usage:
1. Build the app and run it.
kali@kali:/go/src$ cd csrfapp
kali@kali:/go/src/csrfapp$ go run main.go 

2. Start Burp Suite and turn on Foxy Proxy if you have it set up in your browser yet.

3. Login to DVWA by viewing it's ip address in a browser in Kali Linux.
For example, http://10.0.50.33/dvwa then login using the default credentials.

4. Set Security Level in DVWA to low:

Username: admin
Security Level: low
PHPIDS: disabled

5. Open up http://localhost:8000 in a browser in Kali Linux.
Send the GET the request for the /Prizepage page.
Then send the next request which will use a CSRF attack to change the password for the DVWA admin account.

6. Notice how the PHPSESSID variable is the same in the attack request as it was when you logged into DVWA.
PHPSESSID=

7. Finally login to DVWA once more using admin:beh to see how you have just changed the password using CSRF attack.
