💀 Ruby on rails XSS example 
=========================================

This folder contains a sample web application vulnerable to Cross site scription vulnerability on ruby on rails. 

Running the application
------------------------
Docker is required to run the PoC:
```bash
docker-compose build
docker-compose up
```

The application has `users` endpoint vulnerable to the XSS. Visit `http://http://0.0.0.0:3000/users/new` to start. Upload file to the application. Grab blob token from response. Forge new token for a blob object. Pop-up alert.

Write up
--------

To Do