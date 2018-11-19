# Geomys
A small TLS-enabled gopher server for OpenBSD

- unveil(2) and pledge(2)
- Drops privileges after binding to port
- Accepts TLS connection and spits out a gopher line

    $ cd src/
    $ make key
    $ make
    $ doas ./geomys

    $ client.sh
