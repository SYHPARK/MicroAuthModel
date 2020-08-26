#ref: https://sandilands.info/sgordon/apache-web-server-and-certificates

#create CA
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out cakey.pem&&
echo -e "\n[*]Done1\n"&&

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\nwww.example.com\n\n" | openssl req -new -x509 -key cakey.pem -out cacert.pem -days 1095&&
echo -e "\n[*]Done2\n"&&

mkdir demoCA;
mkdir demoCA/certs;
mkdir demoCA/crl;
mkdir demoCA/newcerts;
mkdir demoCA/private;
touch demoCA/index.txt;
echo 02 > demoCA/serial;
mv cacert.pem demoCA/;
mv cakey.pem demoCA/private;

#create certificate for the webserver
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out privkey-www.example.com.pem&&
echo -e "\n[*]Done3\n"&&

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\nwww.example.com\n\n\n\n" | openssl req -new -key privkey-www.example.com.pem -out certreq-www.example.com.csr&&
echo -e "\n[*]Done4\n"&&

openssl ca -in certreq-www.example.com.csr -out cert-www.example.com.pem&&
echo -e "\n[*]Done5\n"&&

cp demoCA/cacert.pem cert-ourca.crt&&
echo -e "\n[*]Done6\n"&&

openssl verify -CAfile cert-ourca.crt cert-www.example.com.pem
echo -e "\n[*]Done7\n"&&

#openssl req -new -x509 -key cakey.pem -out cacert.pem -days 1095;

#openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out privkey-www.example.com.pem;

#echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\nwww.yongbakss.com\n\n\n\n" | openssl req -new -key privkey-www.example.com.pem -out certreq-www.example.com.csr;

#echo -e "authorityKeyIdentifier = keyid, issuer\nbasicConstraints = CA : FALSE\nkeyUsage = digitalSignature, nonrepudiation, keyEncipherment, dataEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = www.yongbakss.com" > ./san-www.example.com.ext;

#cp cacert.pem cert-ourca.crt;

#openssl x509 -req -in certreq-www.example.com.csr -CA cert-ourca.crt -CAkey cakey.pem -CAcreateserial -out cert-www.example.com.pem -days 825 -sha256 -extfile san-www.example.com.ext;

#openssl verify -CAfile cert-ourca.crt cert-www.example.com.pem

