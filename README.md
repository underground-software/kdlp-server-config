# kdlp-server-config


```
user <-|
      /
     /
    /
SSL/
 |/
  nginx<->|             |->databse,APIS
           \           /
   	    |<->wsgi<-|
            |<->wsgi<-|
               ...
  	    |<->wsgi<-|
           /	       \
   auth<->|             |<->management
```

### Servers

|name|type|implementation|purpose|handles|internal|
|--|--|--|--|--|--|
|sol|nginx|config here|SSL and reverse proxy|all external HTTP{,S}||
|venus|wsgi|[auth.py](https://github.com/underground-software/auth.py)|auth server|^/login$|/check (auth_request) and /logout|
|earth|wsgi|[md.py](https://github.com/underground-software/md.py)|serve core .md website|^/$ and ^.\*.md$||
|moon|static|config here|static data (non .md)|default handler||
|mars|wsgi|[gam.py](https://github.com/underground-software/gam.py)|^/US$ and ^/game$||
|
|pluto|fcgi|config here|serves cgit & git |^/cgit.\*$||

## Databases

|name|used by|purpose|
|--|--|--|
|users.db|auth.py|db of valid users with password hashes|
|sessions.db|auth.py|db of active sessions|
