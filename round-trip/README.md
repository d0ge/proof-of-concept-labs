💀 Ruby-SAML round trip vulnerability 
=========================================

This folder contains a sample web application vulnerability to SAML [Ruby SAML allows a SAML authentication bypass due to DOCTYPE handling](https://github.com/advisories/GHSA-4vc4-m8qh-g8jm)

Running the application
------------------------
Docker is required to run the PoC:
```bash
docker-compose build
docker-compose up
```


Write up
--------

[SAML roulette: the hacker always wins](https://portswigger.net/research/saml-roulette-the-hacker-always-wins)