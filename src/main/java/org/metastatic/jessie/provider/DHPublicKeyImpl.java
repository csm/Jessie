package org.metastatic.jessie.provider;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class DHPublicKeyImpl implements DHPublicKey
{
    private final BigInteger y;
    private final DHParameterSpec params;

    public DHPublicKeyImpl(BigInteger y, DHParameterSpec params) {
        this.y = y;
        this.params = params;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public DHParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
