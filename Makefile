.PHONY: dep
dep:
	@dep ensure

.PHONY: serve
serve: server.crt
	@go run main.go

.PHONY: clean
clean:
	@rm -f server.key server.csr server.crt

server.key:
	@openssl genrsa 2048 > server.key

server.csr: server.key
	@openssl req -new -key server.key > server.csr

server.crt: server.csr
	@openssl x509 -days 3650 -req -signkey server.key < server.csr > server.crt
