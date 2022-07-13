# Exploitation and Sample Vulnerable Application of the JWT Null Signature with/without DER encoding
This folder contains a sample web application vulnerable to [CVE-2022-21449](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/), a vulnerability in the Java JDKs 15 to 18 allowing to bypass signature checks using ECDSA signatures (based on elliptic curves).
Original idea belongs to DataDog [project](https://github.com/DataDog/security-labs-pocs/tree/main/proof-of-concept-exploits/jwt-null-signature-vulnerable-app)
and was inspired by [Spring Cloud GCP IAP Authentication Example](https://github.com/GoogleCloudPlatform/spring-cloud-gcp/tree/main/spring-cloud-gcp-samples/spring-cloud-gcp-security-iap-sample)
Application extract user identity from a pre-authenticated header `x-goog-iap-jwt-assertion`


## Running the application
Docker is required to run the PoC:

```
docker build -t spring-gcp-poc .
docker run --name=spring-gcp-poc --rm -p8008:8008 -it spring-gcp-poc
```

The application has `admin` endpoint that requires authenticating with a valid JWT signed by [google-iap-key](https://www.gstatic.com/iap/verify/public_key-jwk) 


```
$ curl http://localhost:8008/admin -sSL -D-
HTTP/1.1 401 
Content-Type: text/plain;charset=UTF-8
Content-Length: 82
Date: Wed, 13 Jul 2022 14:27:56 GMT

Authorized header x-goog-iap-jwt-assertion required to get access to this endpoint
```

Specifying an invalid JWT (for instance, signed with any EC256 key) returns an error as well:
```
curl http://localhost:8008/admin -sSL -D- -H "x-goog-iap-jwt-assertion: AAAA.AAAA.AAAA" 
HTTP/1.1 401 
Content-Type: text/plain;charset=UTF-8
Content-Length: 89
Date: Wed, 13 Jul 2022 14:37:29 GMT
```
## Notes

This demo makes of use of the library [com.nimbusds.nimbus-jose-jwt](https://bitbucket.org/connect2id/nimbus-jose-jwt/src/master/) library before version 9.22 (2022-04-22).

## Credits

* Disclosure: https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/ by Neil Madden
* DataDog Sample Vulnerable Application: Thomas Etrillard, [Christophe Tafani-Dereeper](https://twitter.com/christophetd)
* This repository: [d4d](https://twitter.com/d4d89704243)