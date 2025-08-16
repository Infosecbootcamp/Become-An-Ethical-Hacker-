# Cross Site Scripting-Example
This repo is the code from Become An Ethical Hacker, Chapter 14: Attacking Webapps. CSS, or Cross Site Scripting is when an attacker is able to inject malicious scripts into 
the site and hijack control of it.

# Prequisites
Create an SSL cert, but if not then the program will serve non-TLS so it's ok not to.

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
kali@kali:/go/src$ mkdir css-app
kali@kali:/go/src$ cd css-app
kali@kali:/go/src/css-app$ go run main_insecure.go 

2. Visit the site at http://127.0.0.1:8080 for non TLS and http://127.0.0.1:8000 for TLS.

3. Enter <script>alert("pwned!")</script> in the input form and click submit.
You should now see the exploited site is displayed the message arbitrarily.

4. Make main_secure.go and change the import "text/template" to "html/template". Run main_secure.go (remove main_insecure.go first, can't have two files with package main in the same directory).

5. Visit the site at http://127.0.0.1:8080 for non TLS and http://127.0.0.1:8000 for TLS.

6. Enter <script>alert("pwned!")</script> in the input form and click submit.
You should now see the exploited site is not displaying the message, but instead it is shown above the input box.
