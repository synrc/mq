EMQ XIO
=======

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

Credits
=======

* Maxim Sokhatsky
