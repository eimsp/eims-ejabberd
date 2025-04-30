# Ejabberd modules and demo client for EIMS

* "Converse.js" xmpp-client is used for UI demo
* "CJaC" (Corporate Jabber Client) corporate xmpp-client with an administration panel can be got from https://github.com/eimsp/cjac

## Installation

1. Create root dir of project (for example eims) and "git clone https://github.com/eimsp/eims-ejabberd.git" in that dir.
2. Install erlang , ejabberd (to eims/ejabberd), install necessary additional 3rd-party modules for ejabberd (on admin discretion)
3. Use yml-sample (ejabberd.yml) from eims/eims-ejabberd/etc to configure ejabberd for your environment
4. Run ./eims/eims-ejabberd/setup-dev.sh script to create symlinks and copy necessary files to ejabberd dir (./ejabberd).
5. Register "chat" application in the backend of Integrated Service. Possibly, chat application needs special permission to not show "allow/deny" dialog.
6. Install Nginx with eims.conf (from eims/eims-ejabberd/etc) in dir /etc/nginx/conf.d, eims/eims-ejabberd/www is a dir for Nginx with Converse.js
7. Create docker image using command "docker build --no-cache -t eims/psql:145" in dir ./eims-ejabberd.

### Use ejabberd with Integrated Service locally in development processes

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
 
Worth noting, ejabberd can download and install certificates from letsencrypt itself but then nginx must be configured properly to pass the challenge request to ejabberd 

## Chat application fields for your Integrated Service (iservice)

* Name: iservice
* Domain: iservice.com
* URLs: https://iservice.com/api
* Redirect URLs: https://localhost/iservice/server_auth 

for local testing (config etc/ejabberd.yml, then ejabberd also handles http  is not used), following fields can be used:
* Name: chat
* Domain: localhost
* URLs: https://localhost/ for Converse.js and https://localhost/cjac for CJaC


