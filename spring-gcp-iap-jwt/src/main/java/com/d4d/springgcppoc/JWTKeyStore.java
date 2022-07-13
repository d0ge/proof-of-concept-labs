package com.d4d.springgcppoc;

import java.security.interfaces.ECPublicKey;
import java.util.Optional;

/**
 * A store containing the JWT keys we can use to verify a JWT header.
 */
public interface JWTKeyStore {
    /**
     * Find the key with the given key id and algorithm
     *
     * @param keyId     key id
     * @param algorithm signing algorithm
     */
    Optional<ECPublicKey> getKey(String keyId, String algorithm);
}
