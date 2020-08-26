openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out cakey.pem&&
echo -e "\n[*]Done 1\n";

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\nwww.example.com\n\n" | openssl req -new -x509 -key cakey.pem -out cacert.pem -days 1095&&
echo -e "\n[*]Done 2\n";

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out privkey-www.example.com.pem&&
echo -e "\n[*]Done 3\n";

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\nwww.example.com\n\n\n\n" | openssl req -new -key privkey-www.example.com.pem -out certreq-www.example.com.csr&&
echo -e "\n[*]Done 4\n";

echo -e "authorityKeyIdentifier = keyid, issuer\nbasicConstraints = CA : FALSE\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = www.example.com" > ./san-www.example.com.ext&&
echo -e "\n[*]Done 5\n";

cp cacert.pem cert-ourca.crt&&
echo -e "\n[*]Done 6\n";

openssl x509 -req -in certreq-www.example.com.csr -CA cert-ourca.crt -CAkey cakey.pem -CAcreateserial -out cert-www.example.com.pem -days 825 -sha256 -extfile san-www.example.com.ext&&
echo -e "\n[*]Done 7\n";

openssl verify -CAfile cert-ourca.crt cert-www.example.com.pem&&
echo -e "\n[*]Done 8\n";
