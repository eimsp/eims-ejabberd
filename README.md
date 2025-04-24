# Ejabberd modules and demo client for EIMS

* "Converse.js" xmpp-client is used for UI demo
* "CJaC" (Corporate Jabber Client) corporate xmpp-client with an administration panel can be got from https://github.com/eimsp/cjac

## Installation

1. Create root dir of project (for example eims) and "git clone https://github.com/eimsp/eims-ejabberd.git" in that dir.
2. Install erlang, ejabberd (to eims/ejabberd), install necessary additional 3rd-party modules for ejabberd (on admin discretion)
3. Use yml-samples from ./eims/etc to configure ejabberd for your environment
4. Run setup-dev.sh script to create symlinks and copy necessary files to ejabberd dir (./ejabberd).
5. Register "chat" application in Integrated Service backend. Possibly, chat application needs special permission to not show "allow/deny" dialog.
6. Install Nginx, ./www is a dir for Nginx with Converse.js (see https://github.com/eimsp/docker-eims/-/blob/main/conf/eims.conf?ref_type=heads)

### Use ejabberd with Integrated Service locally 

Create user for example "ejabberd" in system.
Make hard-link to ./eims in dir ~/.ejabberd-modules/sources/ .

You can setup ejabberd without installing in your system:

    ./configure --with-rebar=rebar3 --enable-pgsql
    make dev

Make hard-link to (or copy) ./eims/www in dir ./ejabberd/eims/.  
Copy from ./eims/etc:  
script start-dev.sh to ejabberd dir (./ejabberd), 
ejabberd.yaml.development in ./ejabberd/conf/ejabberd.yaml and correct "Path" in ejabberd.yaml, 
sys.config to ./ejabberd/rel. 

Or use script./eims/setup-dev.sh and then you can correct "Path" in ejabberd.yaml.
                               
Start application:  

    ./ejabberd/start-dev.sh     
 or 
   
    ./ejabberd/rebar3 shell --name ejabberd@localhost      
 
Alternatively
Command line example for running ejabberd without install (please adjust to your paths before running):
```shell script
make
EIMS_PROJECT_ROOT=~/dev 
EJABBERD_CONFIG_PATH=$EIMS_PROJECT_ROOT/eims/etc/ejabberd.yml.development erl -pa ebin -pa deps/*/ebin -s ejabberd
```

Worth noting, ejabberd can download and install certificates from letsencrypt itself but then nginx must be configured properly to pass the challenge request to ejabberd 

## Chat application fields for your Integrated Service (iservice)

* Name: chat
* Domain: chat.iservice.com
* URLs: https://chat.iservice.com/ for Converse.js

for local testing (config ./etc/ejabberd.yml.development, then ejabberd also handles http and nginx is not used), following fields can be used:
* Name: chat
* Domain: localhost
* Redirect URLs: http://localhost:5280/ for Converse.js


