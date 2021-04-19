openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out cakey.pem&&
echo -e "\n[*]Done 1\n";

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\n$1\n\n" | openssl req -new -x509 -key cakey.pem -out cacert.pem -days 1095&&
echo -e "\n[*]Done 2\n";

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out privkey-$1.pem&&
echo -e "\n[*]Done 3\n";

echo -e "KR\nDaejeon\nYuseong\nKAIST\nCA\n$1\n\n\n\n" | openssl req -new -key privkey-$1.pem -out certreq-$1.csr&&
echo -e "\n[*]Done 4\n";

echo -e "authorityKeyIdentifier = keyid, issuer\nbasicConstraints = CA : FALSE\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = $1" > ./san-$1.ext&&
echo -e "\n[*]Done 5\n";

cp cacert.pem cert-ourca.crt&&
echo -e "\n[*]Done 6\n";

openssl x509 -req -in certreq-$1.csr -CA cert-ourca.crt -CAkey cakey.pem -CAcreateserial -out cert-$1.pem -days 825 -sha256 -extfile san-$1.ext&&
echo -e "\n[*]Done 7\n";

openssl verify -CAfile cert-ourca.crt cert-$1.pem&&
echo -e "\n[*]Done 8\n";
