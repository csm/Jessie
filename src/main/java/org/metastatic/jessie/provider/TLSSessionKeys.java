package org.metastatic.jessie.provider;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Preconditions;

/**
 * Copyright (C) 2013 Memeo, Inc.
 * All Rights Reserved
 */
public class TLSSessionKeys implements SecretKey
{
    private final byte[] keyMaterial;
    private final int keylen, maclen, ivlen;
    private boolean isDestroyed = false;

    public TLSSessionKeys(byte[] keyMaterial, int keylen, int maclen, int ivlen)
    {
        Preconditions.checkNotNull(keyMaterial);
        Preconditions.checkArgument(keyMaterial.length >= 2 * (keylen + maclen + ivlen), "key material must be long enough for all keys");
        this.keyMaterial = keyMaterial.clone();
        this.keylen = keylen;
        this.maclen = maclen;
        this.ivlen = ivlen;
    }

    private void checkDestroyed()
    {
        if (isDestroyed)
            throw new IllegalStateException("key is destroyed");
    }

    public byte[] getClientWriteMACKey()
    {
        checkDestroyed();
        byte[] clientWriteMACKey = new byte[maclen];
        System.arraycopy(keyMaterial, 0, clientWriteMACKey, 0, maclen);
        return clientWriteMACKey;
    }

    public byte[] getServerWriteMACKey()
    {
        checkDestroyed();
        byte[] serverWriteMACKey = new byte[maclen];
        System.arraycopy(keyMaterial, maclen, serverWriteMACKey, 0, maclen);
        return serverWriteMACKey;
    }

    public byte[] getClientWriteKey()
    {
        checkDestroyed();
        byte[] clientWriteKey = new byte[keylen];
        System.arraycopy(keyMaterial, 2 * maclen, clientWriteKey, 0, keylen);
        return clientWriteKey;
    }

    public byte[] getServerWriteKey()
    {
        checkDestroyed();
        byte[] serverWriteKey = new byte[keylen];
        System.arraycopy(keyMaterial, (2 * maclen) + keylen, serverWriteKey, 0, keylen);
        return serverWriteKey;
    }

    public byte[] getClientWriteIV()
    {
        checkDestroyed();
        byte[] clientWriteIV = new byte[ivlen];
        System.arraycopy(keyMaterial, 2 * (maclen + keylen), clientWriteIV, 0, ivlen);
        return clientWriteIV;
    }

    public byte[] getServerWriteIV()
    {
        checkDestroyed();
        byte[] serverWriteIV = new byte[ivlen];
        System.arraycopy(keyMaterial, 2 * (keylen + maclen) + ivlen, serverWriteIV, 0, ivlen);
        return serverWriteIV;
    }

    @Override
    public String getAlgorithm()
    {
        return "TLS";
    }

    @Override
    public String getFormat()
    {
        return "RAW";
    }

    @Override
    public byte[] getEncoded()
    {
        checkDestroyed();
        return keyMaterial.clone();
    }

    public TLSSessionKeys xor(TLSSessionKeys other)
    {
        Preconditions.checkNotNull(other);
        Preconditions.checkArgument(keyMaterial.length == other.keyMaterial.length);
        Preconditions.checkArgument(keylen == other.keylen);
        Preconditions.checkArgument(maclen == other.maclen);
        Preconditions.checkArgument(ivlen == other.ivlen);
        checkDestroyed();
        other.checkDestroyed();
        byte[] xored = new byte[keyMaterial.length];
        for (int i = 0; i < keyMaterial.length; i++)
            xored[i] = (byte) (keyMaterial[i] ^ other.keyMaterial[i]);

        return new TLSSessionKeys(xored, keylen, maclen, ivlen);
    }

    @Override
    public boolean isDestroyed()
    {
        return isDestroyed;
    }

    @Override
    public void destroy()
    {
        if (!isDestroyed)
        {
            Arrays.fill(keyMaterial, (byte) 0);
            isDestroyed = true;
        }
    }
}
