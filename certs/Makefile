all: server-cert.pem

ca-cert.pem:
	@openssl req -x509 -newkey rsa:4096 -days 365 -nodes -sha256 -keyout ca-key.pem -out $@ -subj "/C=FR/ST=Occitanie/L=Toulouse/O=grpcoauth/OU=Cloud/CN=localhost/emailAddress=admin@localhost"
	@openssl x509 -in $@ -sha256 -noout -text

server-req.pem:
	@openssl req -newkey rsa:4096 -nodes -sha256 -keyout server-key.pem -out $@ -subj "/C=FR/ST=Occitanie/L=Toulouse/O=grpcoauth/OU=Cloud/CN=localhost/emailAddress=admin@localhost"


server-cert.pem: ca-cert.pem server-req.pem server-ext.cnf
	@openssl x509 -req -in server-req.pem -sha256 -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out $@ -extfile server-ext.cnf
	@openssl x509 -in $@ -sha256 -noout -text


install:
	@#see: https://apple.stackexchange.com/questions/215205/how-to-add-a-self-signed-root-ca-and-always-trust-it-from-cli-on-osx
	@security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" ca-cert.pem
