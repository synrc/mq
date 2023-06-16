SYNRC 📟 MQ
===========

Features
--------

* Erlang/OTP
* MQTT protocol 5.0
* TCP/TLS/WebSocket/WSS/MQTT/MQTTS

Install
-------

Here is example how to install SYNRC MQ server from macOS:

```
$ brew install erlang elixir
$ git clone git@github.com:synrc/mq && cd mq
$ mix deps.get
$ iex -S mix
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

* Namdak Tonpa

