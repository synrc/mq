SYNRC 📟 MQ
===========

Features
--------

* C99
* TCP/UDP/TLS/QUIC

Install
-------

```
$ sudo apt install libuv1-dev libmbedtls-dev
$ gcc -o mq mq.c -luv -lmbedtls -lmbedx509 -lmbedcrypto
```

Example of success:

```
$ ./mq
QUIC support requires msquic integration
MQTT v5 server running on ports 1883 (TCP), 8883 (TLS), 14567 (UDP)
```

Credits
=======

* Namdak Tonpa

