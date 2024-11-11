@echo off
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -aes256 -out private.key 2048


rem "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" rsa -in private.key -out private.key

"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" req -new -x509 -nodes -sha1 -key private.key -out certificate.crt -days 8

"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt -certfile more.crt

set /p id="Enter private key file pass: "
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool" sign /t http://timestamp.globalsign.com/scripts/timstamp.dll /f "%UserProfile%\Desktop\repo\sense\version_1\certificate.pfx" /p %id% "dist\sense.exe"
pause
