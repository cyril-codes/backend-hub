# Backend with JWT Authentication service

Backend REST API written in Go with a simple JWT Authentication service. This
application will be the entry point of any frontend that wants to access other
services.

## Install

```sh
# If you do not have go installed, follow this link https://go.dev/doc/install

# Clone the repository and navigate into it
git clone https://github.com/cyril-codes/backend-hub.git && cd backend-hub

# Create a new folder named jwt and navigate into it
mkdir jwt && cd jwt

# Create a new set of private/public RS256 keys used for the JWT signatures
# Don't add any passphrase
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key

openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```

## Run

```sh
# Build and run the application
make run

# The application will be launched on port :3000 by default, 
# If you wish to change it you can modify the argument used
# in the NewServer function call inside the main.go file.
```
