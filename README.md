Name
====

forward-proxy-nginx-module - A HTTP/SOCKS5 forward proxy server based on Nginx Stream Module.

Table of Contents
=================

* [Name](#name)
* [Build](#build)
* [Synopsis](#synopsis)
* [Directives](#directives)
* [Demo](#demo)

Build
=====

```bash
cd nginx
./configure --add-module=/path/to/forward-proxy-nginx-module --with-stream
make
make install
```

[Back to TOC](#table-of-contents)


Synopsis
========
```nginx
stream {
    resolver 8.8.8.8;
    server {
        listen  0.0.0.0:12345;
        fproxy_protocols HTTP SOCKS5;
        fproxy_auth_methods BASIC;
        fproxy_user_passwd john 12345678;
        fproxy_user_passwd lucy abcdefgh;
    }
}
```

[Back to TOC](#table-of-contents)

Directives
==========

Most of the diretives are just the counterparts of `ngx_stream_proxy_module`
under a different name except the first serveral ones.

**Note** UDP is not supported, so don't add `udp` on `listen` directive when setting `fproxy_protocols`.

* [fproxy_protocols](#fproxy_protocols)
* [fproxy_auth_methods](#fproxy_auth_methods)
* [fproxy_user_passwd](#fproxy_user_passwd)
* [fproxy_negotiate_timeout](#fproxy_negotiate_timeout)
* [fproxy_response_timeout](#fproxy_response_timeout)
* [fproxy_bind](#fproxy_bind)
* [fproxy_socket_keepalive](#fproxy_socket_keepalive)
* [fproxy_connect_timeout](#fproxy_connect_timeout)
* [fproxy_timeout](#fproxy_timeout)
* [fproxy_buffer_size](#fproxy_buffer_size)
* [fproxy_upload_rate](#fproxy_upload_rate)
* [fproxy_download_rate](#fproxy_download_rate)
* [fproxy_next_upstream](#fproxy_next_upstream)
* [fproxy_next_upstream_tries](#fproxy_next_upstream_tries)
* [fproxy_next_upstream_timeout](#fproxy_next_upstream_timeout)
* [fproxy_half_close](#fproxy_half_close)

[Back to TOC](#table-of-contents)

fproxy_protocols
----------------

**syntax:** *fproxy_protocols HTTP SOCKS5*

**default:** *-*

**context:** *server*

Enables forward proxy. Can Set multiple protocols supported.

[Back to TOC](#directives)

fproxy_auth_methods
-------------------

**syntax:** *fproxy_auth_methods BASIC*

**default:** *-*

**context:** *server*

Specifies the authentication methods supported. (Currently only Basic Auth.) If no method is set, no authentication is done.

[Back to TOC](#directives)

fproxy_user_passwd
------------------

**syntax:** *fproxy_user_passwd username password*

**default:** *-*

**context:** *server*

Add the specified credential to server used for Basic authentication.

[Back to TOC](#directives)

fproxy_negotiate_timeout
------------------------

**syntax:** *fproxy_negotiate_timeout time*

**default:** *fproxy_negotiate_timeout 60s*

**context:** *stream, server*

Sets the timeout for completing the negotiation with client. (Beforing connecting to upstream)

[Back to TOC](#directives)

fproxy_response_timeout
-----------------------

**syntax:** *fproxy_response_timeout time*

**default:** *fproxy_response_timeout 30s*

**context:** *stream, server*

Sets the timeout for send response to client.

[Back to TOC](#directives)

fproxy_bind
-----------

**syntax:** *fproxy_bind address [transparent] | off*

**default:** *-*

**context:** *stream, server*

Makes outgoing connections to a proxied server originate from the specified local IP address. Parameter value can contain variables (1.11.2). The special value off cancels the effect of the proxy_bind directive inherited from the previous configuration level, which allows the system to auto-assign the local IP address.

The transparent parameter allows outgoing connections to a proxied server originate from a non-local IP address, for example, from a real IP address of a client:

proxy_bind $remote_addr transparent;
In order for this parameter to work, it is usually necessary to run nginx worker processes with the superuser privileges. On Linux it is not required (1.13.8) as if the transparent parameter is specified, worker processes inherit the CAP_NET_RAW capability from the master process. It is also necessary to configure kernel routing table to intercept network traffic from the proxied server.

[Back to TOC](#directives)

fproxy_socket_keepalive
-----------------------

**syntax:** *fproxy_socket_keepalive on | off*

**default:** *fproxy_socket_keepalive off*

**context:** *stream, server*

Configures the “TCP keepalive” behavior for outgoing connections to a proxied server. By default, the operating system’s settings are in effect for the socket. If the directive is set to the value “on”, the SO_KEEPALIVE socket option is turned on for the socket.

[Back to TOC](#directives)

fproxy_connect_timeout
----------------------

**syntax:** *fproxy_connect_timeout time*

**default:** *fproxy_connect_timeout 60s*

**context:** *stream, server*

Defines a timeout for establishing a connection with the upstream server.

[Back to TOC](#directives)

fproxy_timeout
--------------

**syntax:** *fproxy_timeout time*

**default:** *fproxy_timeout 10m*

**context:** *stream, server*

Sets the timeout between two successive read or write operations on client or proxied server connections. If no data is transmitted within this time, the connection is closed.

[Back to TOC](#directives)

fproxy_buffer_size
------------------

**syntax:** *fproxy_buffer_size size*

**default:** *fproxy_buffer_size 16k*

**context:** *stream, server*

Sets the size of the buffer used for reading data from the proxied server. Also sets the size of the buffer used for reading data from the client.

[Back to TOC](#directives)

fproxy_upload_rate
------------------

**syntax:** *fproxy_upload_rate rate*

**default:** *fproxy_upload_rate 0*

**context:** *stream, server*

Limits the speed of reading the data from the client. The rate is specified in bytes per second. The zero value disables rate limiting. The limit is set per a connection, so if the client simultaneously opens two connections, the overall rate will be twice as much as the specified limit.

Parameter value can contain variables. It may be useful in cases where rate should be limited depending on a certain condition:

```nginx
map $slow $rate {
    1     4k;
    2     8k;
}

proxy_upload_rate $rate;
```

[Back to TOC](#directives)

fproxy_download_rate
--------------------

**syntax:** *fproxy_download_rate rate*

**default:** *fproxy_download_rate 0*

**context:** *stream, server*

Limits the speed of reading the data from the proxied server. The rate is specified in bytes per second. The zero value disables rate limiting. The limit is set per a connection, so if the client simultaneously opens two connections, the overall rate will be twice as much as the specified limit.

Parameter value can contain variables. It may be useful in cases where rate should be limited depending on a certain condition:

```nginx
map $slow $rate {
    1     4k;
    2     8k;
}

proxy_download_rate $rate;
```

[Back to TOC](#directives)

fproxy_next_upstream
--------------------

**syntax:** *fproxy_next_upstream on | off*

**default:** *fproxy_next_upstream on*

**context:** *stream, server*

When a connection to the proxied server cannot be established, determines whether a client connection will be passed to the next server.

Passing a connection to the next server can be limited by the number of tries and by time.

[Back to TOC](#directives)

fproxy_next_upstream_tries
--------------------------

**syntax:** *fproxy_next_upstream_tries number*

**default:** *fproxy_next_upstream_tries 0*

**context:** *stream, server*

Limits the number of possible tries for passing a connection to the next server. The 0 value turns off this limitation.

[Back to TOC](#directives)

fproxy_next_upstream_timeout
----------------------------

**syntax:** *fproxy_next_upstream_timeout time*

**default:** *fproxy_next_upstream_timeout 0*

**context:** *stream, server*

Limits the time allowed to pass a connection to the next server. The 0 value turns off this limitation.

[Back to TOC](#directives)

fproxy_half_close
-----------------

**syntax:** *fproxy_half_close on | off*

**default:** *fproxy_half_close off*

**context:** *stream, server*

Enables or disables closing each direction of a TCP connection independently (“TCP half-close”). If enabled, proxying over TCP will be kept until both sides close the connection.

[Back to TOC](#directives)

Demo
========

without authentication
----------------------

```bash
❯ curl --proxy "http://localhost:12345" "http://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "Proxy-Connection": "Keep-Alive",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-6580699d-02c75cfa52269cb261fca28f"
  },
  "origin": "1.1.1.1",
  "url": "http://httpbin.org/get"
}
❯ curl --proxy "http://localhost:12345" "https://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-658069a4-0dbc2d5c2962b6564a91ec70"
  },
  "origin": "1.1.1.1",
  "url": "https://httpbin.org/get"
}
❯ curl --proxy "socks5://localhost:12345" "http://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-658069a9-4280fbb01654eac94762fa2a"
  },
  "origin": "1.1.1.1",
  "url": "http://httpbin.org/get"
}
❯ curl --proxy "socks5h://localhost:12345" "https://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-65806b85-128c32f2068e5df7049dd6b5"
  },
  "origin": "1.1.1.1",
  "url": "https://httpbin.org/get"
}
```

with authentication
-------------------

```bash
❯ curl --proxy-basic --proxy-user john:12345678 --proxy "http://localhost:12345" "http://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "Proxy-Connection": "Keep-Alive",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-65806c73-2401186b3be60335545e0437"
  },
  "origin": "1.1.1.1",
  "url": "http://httpbin.org/get"
}
❯ curl --proxy-basic --proxy-user lucy:abcdefgh --proxy "socks5://localhost:12345" "https://httpbin.org/get"
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.1.2",
    "X-Amzn-Trace-Id": "Root=1-65806cb5-516311e673540cf330733d31"
  },
  "origin": "1.1.1.1",
  "url": "https://httpbin.org/get"
}
❯ curl --proxy-basic --proxy-user john:88888888 --proxy "http://localhost:12345" "https://httpbin.org/get"
curl: (56) CONNECT tunnel failed, response 407
❯ curl --proxy-basic --proxy-user david:12341234 --proxy "socks5://localhost:12345" "https://httpbin.org/get"
curl: (97) User was rejected by the SOCKS5 server (1 1).
❯ curl --proxy "socks5://localhost:12345" "https://httpbin.org/get"
curl: (97) No authentication method was acceptable.
```

[Back to TOC](#table-of-contents)
