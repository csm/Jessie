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
    public static class Builder
    {
        private byte[] clientWriteMACKey;
        private byte[] serverWriteMACKey;
        private byte[] clientWriteKey;
        private byte[] serverWriteKey;
        private byte[] clientWriteIV;
        private byte[] serverWriteIV;

        public Builder withClientWriteMACKey(byte[] b, int offset, int length)
        {
            clientWriteMACKey = new byte[length];
            System.arraycopy(b, offset, clientWriteMACKey, 0, length);
            return this;
        }

        public Builder withServerWriteMACKey(byte[] b, int offset, int length)
        {
            serverWriteMACKey = new byte[length];
            System.arraycopy(b, offset, serverWriteMACKey, 0, length);
            return this;
        }

        public Builder withClientWriteKey(byte[] b, int offset, int length)
        {
            clientWriteKey = new byte[length];
            System.arraycopy(b, offset, clientWriteKey, 0, length);
            return this;
        }

        public Builder withServerWriteKey(byte[] b, int offset, int length)
        {
            serverWriteKey = new byte[length];
            System.arraycopy(b, offset, serverWriteKey, 0, length);
            return this;
        }

        public Builder withClientWriteIV(byte[] b, int offset, int length)
        {
            clientWriteIV = new byte[length];
            System.arraycopy(b, offset, clientWriteIV, 0, length);
            return this;
        }

        public Builder withServerWriteIV(byte[] b, int offset, int length)
        {
            serverWriteIV = new byte[length];
            System.arraycopy(b, offset, serverWriteIV, 0, length);
            return this;
        }

        public TLSSessionKeys build()
        {
            return new TLSSessionKeys(clientWriteMACKey, serverWriteMACKey, clientWriteKey, serverWriteKey,
                    clientWriteIV, serverWriteIV);
        }
    }

    private final byte[] clientWriteMACKey;
    private final byte[] serverWriteMACKey;
    private final byte[] clientWriteKey;
    private final byte[] serverWriteKey;
    private final byte[] clientWriteIV;
    private final byte[] serverWriteIV;
    private boolean isDestroyed = false;

    public TLSSessionKeys(byte[] clientWriteMACKey, byte[] serverWriteMACKey,
                          byte[] clientWriteKey, byte[] serverWriteKey,
                          byte[] clientWriteIV, byte[] serverWriteIV)
    {
        this.clientWriteMACKey = clientWriteMACKey.clone();
        this.serverWriteMACKey = serverWriteMACKey.clone();
        this.clientWriteKey = clientWriteKey.clone();
        this.serverWriteKey = serverWriteKey.clone();
        this.clientWriteIV = clientWriteIV.clone();
        this.serverWriteIV = serverWriteIV.clone();
    }

    private void checkDestroyed()
    {
        if (isDestroyed)
            throw new IllegalStateException("key is destroyed");
    }

    public byte[] getClientWriteMACKey()
    {
        checkDestroyed();
        return clientWriteMACKey;
    }

    public byte[] getServerWriteMACKey()
    {
        checkDestroyed();
        return serverWriteMACKey;
    }

    public byte[] getClientWriteKey()
    {
        checkDestroyed();
        return clientWriteKey;
    }

    public byte[] getServerWriteKey()
    {
        checkDestroyed();
        return serverWriteKey;
    }

    public byte[] getClientWriteIV()
    {
        checkDestroyed();
        return clientWriteIV;
    }

    public byte[] getServerWriteIV()
    {
        checkDestroyed();
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
        byte[] ret = new byte[clientWriteMACKey.length + serverWriteMACKey.length + clientWriteKey.length + serverWriteKey.length + clientWriteIV.length + serverWriteIV.length];
        AtomicInteger pos = new AtomicInteger();
        System.arraycopy(clientWriteMACKey, 0, ret, pos.getAndAdd(clientWriteMACKey.length), clientWriteMACKey.length);
        System.arraycopy(serverWriteMACKey, 0, ret, pos.getAndAdd(serverWriteMACKey.length), serverWriteMACKey.length);
        System.arraycopy(clientWriteKey, 0, ret, pos.getAndAdd(clientWriteKey.length), clientWriteKey.length);
        System.arraycopy(serverWriteKey, 0, ret, pos.getAndAdd(serverWriteKey.length), serverWriteKey.length);
        System.arraycopy(clientWriteIV, 0, ret, pos.getAndAdd(clientWriteIV.length), clientWriteIV.length);
        System.arraycopy(serverWriteIV, 0, ret, pos.getAndAdd(serverWriteIV.length), serverWriteIV.length);
        return ret;
    }

    public TLSSessionKeys xor(TLSSessionKeys other)
    {
        byte[] clientWriteMac1 = getClientWriteMACKey().clone();
        byte[] clientWriteMac2 = other.getClientWriteMACKey();
        Preconditions.checkArgument(clientWriteMac1.length == clientWriteMac2.length);
        for (int i = 0; i < clientWriteMac1.length; i++)
            clientWriteMac1[i] = (byte) (clientWriteMac1[i] ^ clientWriteMac2[i]);

        byte[] serverWriteMac1 = getServerWriteMACKey().clone();
        byte[] serverWriteMac2 = other.getServerWriteMACKey();
        Preconditions.checkArgument(serverWriteMac1.length == serverWriteMac2.length);
        for (int i = 0; i < serverWriteMac1.length; i++)
            serverWriteMac1[i] = (byte) (serverWriteMac1[i] ^ serverWriteMac2[i]);

        byte[] clientWrite1 = getClientWriteKey().clone();
        byte[] clientWrite2 = other.getClientWriteKey();
        Preconditions.checkArgument(clientWrite1.length == clientWrite2.length);
        for (int i = 0; i < clientWrite1.length; i++)
            clientWrite1[i] = (byte) (clientWrite1[i] ^ clientWrite2[i]);

        byte[] serverWrite1 = getServerWriteKey().clone();
        byte[] serverWrite2 = other.getServerWriteKey();
        Preconditions.checkArgument(serverWrite1.length == serverWrite2.length);
        for (int i = 0; i < serverWrite1.length; i++)
            serverWrite1[i] = (byte) (serverWrite1[i] ^ serverWrite2[i]);

        byte[] clientIv1 = getClientWriteIV().clone();
        byte[] clientIv2 = other.getClientWriteIV();
        Preconditions.checkArgument(clientIv1.length == clientIv2.length);
        for (int i = 0; i < clientIv1.length; i++)
            clientIv1[i] = (byte) (clientIv1[i] ^ clientIv2[i]);

        byte[] serverIv1 = getServerWriteIV().clone();
        byte[] serverIv2 = other.getServerWriteIV();
        Preconditions.checkArgument(serverIv1.length == serverIv2.length);
        for (int i = 0; i < serverIv1.length; i++)
            serverIv1[i] = (byte) (serverIv1[i] ^ serverIv2[i]);

        return new TLSSessionKeys(clientWriteMac1, serverWriteMac1,
                clientWrite1, serverWrite1, clientIv1, serverIv1);
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
            Arrays.fill(this.clientWriteMACKey, (byte) 0);
            Arrays.fill(this.serverWriteMACKey, (byte) 0);
            Arrays.fill(this.clientWriteKey, (byte) 0);
            Arrays.fill(this.serverWriteKey, (byte) 0);
            Arrays.fill(this.clientWriteIV, (byte) 0);
            Arrays.fill(this.serverWriteIV, (byte) 0);
            isDestroyed = true;
        }
    }
}
