openssl genpkey -algorithm RSA -out priv.pem -pkeyopt rsa_keygen_bits:4096 || exit 1
openssl rsa -in priv.pem -pubout > pub.pem || exit 2
#openssl req -new -x509 -key priv.pem -out cert.pem -days 99999 || exit 3


