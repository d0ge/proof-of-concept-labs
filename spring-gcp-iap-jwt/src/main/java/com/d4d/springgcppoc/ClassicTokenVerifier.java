package com.d4d.springgcppoc;

import java.security.KeyPairGenerator;
import java.security.Signature;

public class ClassicTokenVerifier {

    public ClassicTokenVerifier() {
    }

    public boolean verifyToken(String tokenString){
        try{
            var keys = KeyPairGenerator.getInstance("EC").generateKeyPair();
            var blankSignature = new byte[64];
            var sig = Signature.getInstance("SHA256WithECDSAInP1363Format");
            sig.initVerify(keys.getPublic());
            sig.update(tokenString.getBytes());
            if(sig.verify(blankSignature)){
                return true;
            }
        } catch (final Exception e) {
            return false;
        }
        return false;
    }
}
