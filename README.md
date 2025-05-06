# Extensible & Integrable Messaging System

Extensible & Integrable Messaging System (EIMS) is a modular and extensible messaging system based on ejabberd.
It is designed to be integrated with third-party systems (host service). EIMS integrates into the host service to extend its real-time functions. 

## Ejabberd modules and demo client for EIMS

* "Converse.js" xmpp-client is used for UI demo (https://github.com/eimsp/eims-converse.js) 
* "CJaC" (Corporate Jabber Client) corporate xmpp-client with an administration panel can be got from https://github.com/eimsp/cjac

## Installation

1. Create root dir of the project (for example, eims) and "git clone https://github.com/eimsp/eims-ejabberd.git" in that dir.
2. Install Erlang/OTP version > 25, ejabberd (to eims/ejabberd), install necessary additional 3rd-party modules for ejabberd (on admin discretion)
3. Use yml-sample (ejabberd.yml) from eims/eims-ejabberd/etc to configure ejabberd for your environment
4. Run ./eims/eims-ejabberd/setup-dev.sh script to create symlinks and copy necessary files to ejabberd dir (./ejabberd).
5. Register "chat" application in the backend of Host Service. Possibly, chat application needs special permission to not show "allow/deny" dialog.
6. Install Nginx with eims.conf (from eims/eims-ejabberd/etc) in dir /etc/nginx/conf.d, eims/eims-ejabberd/www is a dir for Nginx with Converse.js
7. Create docker image for PostgresDB using command "docker build --no-cache -t eims/psql:145" in dir eims-ejabberd.

### Use ejabberd with Host Service locally in development processes

Create user with uid=1000, gid=1000 in your system, then you can correct "Path" in ejabberd.yaml and
copy sys.config to ejabberd/rel.

You can set up ejabberd without installing in your system:

    ./configure --with-rebar=rebar3 --enable-pgsql
    make dev


Start DBS:
    Rename docker-compose-dev.yml to docker-compose.yml
    docker-compose up -d

Start application:  

    ./ejabberd/start-dev.sh     
 or 
   
    ./ejabberd/rebar3 shell --name ejabberd@localhost      

Nginx must be configured properly for ports 443 and 80 to pass the challenge request to ejabberd and 
to the correct locations (see eims.conf). In production, make sure that the firewall settings allow traffic on ports 80, 443, 5280 and 5443.

### SSL/TLS certificates

SSL/TLS certificates are required for secure communication between XMPP clients and ejabberd.
You can use self-signed certificates for testing purposes or obtain valid certificates from a 
trusted Certificate Authority (CA) like Let's Encrypt for production environments. Worth noting, ejabberd can download and install certificates from 
letsencrypt itself it is needed at a minimum for a production version.

##  Configuration EIMS for your Host Service (hservice)

EIMS is designed to be integrated with a host service. The host service must provide an API for EIMS to communicate with it using websockets.
The host service can also provide a way to authenticate users of this service and authorize them to access the chat application.

The following parameters are required for EIMS to work application "Chats" (application for p2p and multi-user chats)  in a production environment:
* Domain: eims.domain 
* URLs: https://eims.domain/ for Converse.js and https://eims.domain/cjac for CJaC  
* Host Service URLs: https://hservice.com/api
* Redirect URLs: https://eims.domain/hservice/server_auth 

for local testing any applications (configuration in eims-ejabberd/etc/ejabberd.yml), following params can be used:
* Domain: localhost
* URLs: https://localhost/ for Converse.js, https://localhost/cjac for CJaC etc
* Host Service URLs: https://hservice.com/api
* Redirect URLs: https://localhost/hservice/server_auth 

