package com.d4d.springgcppoc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthorizationService {
    final static Logger logger = LoggerFactory.getLogger(AuthorizationService.class);
    private final String issuerUrl;
    private final String expectedAudience;
    private final JWTKeyStore keyStore;
    private final Clock clock;

    public AuthorizationService() {
        this.issuerUrl = "https://cloud.google.com/iap";
        this.expectedAudience="/projects/1234567890/apps/0987654321";
        this.keyStore = new CachedJWTKeyStore();
        this.clock = Clock.systemUTC();
    }

    private boolean isValidJWT(String tokenString) throws UnauthorizedException {
        try
        {
            final SignedJWT signedJWT = SignedJWT.parse(tokenString);
            final JWSHeader header = signedJWT.getHeader();

            if (header.getAlgorithm() == null)
            {
                return false;
            }
            if (header.getKeyID() == null)
            {
                return false;
            }

            final JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            if (!claims.getAudience().contains(expectedAudience))
            {
                throw new UnauthorizedException(String.format("Expected Audience is %s", expectedAudience));
            }
            if (!claims.getIssuer().equals(issuerUrl))
            {
                throw new UnauthorizedException(String.format("Expected issuer is %s", issuerUrl));
            }

            final Date now = Date.from(Instant.now(clock));
            if (!claims.getIssueTime().before(now))
            {
                return false;
            }
            if (!claims.getExpirationTime().after(now))
            {
                return false;
            }
            if (claims.getSubject() == null)
            {
                throw new UnauthorizedException("Subject is empty");
            }
            if (claims.getClaim("email") == null)
            {
                throw new UnauthorizedException("Email is empty");
            }

            final Optional<ECPublicKey> publicKey = keyStore.getKey(header.getKeyID(), header.getAlgorithm().getName());
            if (!publicKey.isPresent())
            {
                return false;
            }
            final JWSVerifier verifier = new ECDSAVerifier(publicKey.get());
            if (signedJWT.verify(verifier))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (final JOSEException | ParseException e)
        {
            throw new UnauthorizedException(e.getMessage());
        }

    }

    public String getClaim(String jwt, String claim) throws UnauthorizedException {
        if (!isValidJWT(jwt)) {
            throw new UnauthorizedException("Token is invalid");
        }
        try {
            final SignedJWT signedJWT = SignedJWT.parse(jwt);
            final JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getClaim(claim).toString();
        } catch (ParseException e) {
            throw new UnauthorizedException(e.getMessage());
        }
    }

    public String getSubject(String jwt) throws UnauthorizedException {
        return getClaim(jwt,"email");
    }
}
