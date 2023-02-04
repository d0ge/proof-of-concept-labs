💀 Memcached command injection at pylibmc
=========================================

This folder contains a sample web application vulnerable to Memcached command injection at pylibmc library. 

Running the application
------------------------
Docker is required to run the PoC:
```bash
docker-compose -f compose.yaml up
```

The application has `set` endpoint vulnerable to the session injection. Visit `http://127.0.0.1:8000/set/?key=value` to start.

Write up
--------

Full detailed description of vulnerability available at [page](https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/)