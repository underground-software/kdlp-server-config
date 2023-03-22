# kdlp-server-config


```
user <-|
      /
     /
    /
SSL/
 |/
  nginx<->|            |->databse,APIS
           \          /
   	    |<->wsgi<-|
            |<->wsgi<-|
               ...
  	    |<->wsgi<-|
         /	       \
 auth<->|            |<->management
```

