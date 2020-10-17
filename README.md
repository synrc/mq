ERP.UNO MQ
==========
[![Build Status](https://travis-ci.com/erpuno/mq.svg?branch=master)](https://travis-ci.com/erpuno/mq)

Install Erlang

```
$ brew install erlang
```

Install MAD

```
$ curl -fsSL \
   https://git.io/fpYm4 \
   > mad && chmod +x mad \
   && sudo cp mad /usr/local/bin
```

Install XIO Server

```
$ mad get xio/server && cd deps/server
$ mad dep com pla rep
```

Example of success:

```
> Starting emqx on node nonode@nohost
Start mqtt:tcp listener on 127.0.0.1:11883 successfully.
Start mqtt:tcp listener on 0.0.0.0:1883 successfully.
Start mqtt:ws listener on 0.0.0.0:8083 successfully.
Start mqtt:ssl listener on 0.0.0.0:8883 successfully.
Start mqtt:wss listener on 0.0.0.0:8084 successfully.
EMQ X Broker git is running now!
Start http:management listener on 8080 successfully.
Start http:dashboard listener on 18083 successfully.
```

Open admin panel: [http://localhost:18083](http://localhost:18083)
Login/Pass: admin/public

Credits
=======

* Maksym Sokhatsky
* Andrii Zadorozhnii
