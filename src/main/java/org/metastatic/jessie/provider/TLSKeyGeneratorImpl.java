/* TLSKeyGeneratorImpl.java -- The TLS pseudo-random function.
   Copyright (C) 2006  Free Software Foundation, Inc.
   Copyright (C) 2014  Casey Marshall

This file is a part of Jessie, using code from GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */


package org.metastatic.jessie.provider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * TLSv1+ key material generator.
 */
class TLSKeyGeneratorImpl extends KeyGeneratorSpi
{
    // Fields.
    // -------------------------------------------------------------------------

    private final Mac hmac;
    private byte[] a;
    private byte[] seed;
    private byte[] secret;
    private final byte[] buffer;
    private int keyLength, macLength, ivLength;
    private int idx;
    private boolean init;
    private String algName;

    // Constructors.
    // -------------------------------------------------------------------------

    TLSKeyGeneratorImpl(String hmacName) throws NoSuchAlgorithmException
    {
        hmac = Mac.getInstance(hmacName);
        buffer = new byte[hmac.getMacLength()];
        idx = 0;
        init = false;
    }

    // Instance methods.
    // -------------------------------------------------------------------------


    @Override
    protected void engineInit(SecureRandom secureRandom)
    {
        throw new IllegalArgumentException("must be initialized with a TLSKeyGeneratorImpl");
    }

    @Override
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
    {
        if (!(algorithmParameterSpec instanceof TLSKeyGeneratorParameterSpec))
            throw new InvalidAlgorithmParameterException("must be initialized with a TLSKeyGeneratorImpl");
        Arrays.fill(buffer, (byte) 0);
        seed = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getSeed();
        a = seed.clone();
        byte[] secret = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getSecret();
        try
        {
            hmac.init(new SecretKeySpec(secret, hmac.getAlgorithm()));
        }
        catch (InvalidKeyException e)
        {
            throw new InvalidAlgorithmParameterException(e);
        }
        idx = buffer.length;
        init = true;
        keyLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getKeyLength();
        macLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getMacLength();
        ivLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getIVLength();
        algName = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getAlgName();
    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new IllegalArgumentException("must be initialized with a TLSKeyGeneratorImpl");
    }

    @Override
    public SecretKey engineGenerateKey()
    {
        byte[] keyMaterial = new byte[2 * (keyLength + macLength + ivLength)];
        nextBytes(keyMaterial, 0, keyMaterial.length);
        return new TLSSessionKeys(keyMaterial, keyLength, macLength, ivLength);
    }

    private void nextBytes(byte[] buf, int off, int len)
    {
        if (!init)
            throw new IllegalStateException();
        if (buf == null)
            throw new NullPointerException();
        if (off < 0 || off > buf.length || off + len > buf.length)
            throw new ArrayIndexOutOfBoundsException();
        int count = 0;
        if (idx >= buffer.length)
            fillBuffer();
        while (count < len)
        {
            int l = Math.min(buffer.length - idx, len - count);
            System.arraycopy(buffer, idx, buf, off + count, l);
            idx += l;
            count += l;
            if (count < len && idx >= buffer.length)
                fillBuffer();
        }
    }

    // Own methods.
    // -------------------------------------------------------------------------

    /*
     * The PRF is defined as:
     *
     *   PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
     *                              P_SHA-1(S2, label + seed);
     *
     * P_hash is defined as:
     *
     *   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                          HMAC_hash(secret, A(2) + seed) +
     *                          HMAC_hash(secret, A(3) + seed) + ...
     *
     * And A() is defined as:
     *
     *   A(0) = seed
     *   A(i) = HMAC_hash(secret, A(i-1))
     */
    private synchronized void fillBuffer()
    {
        // Compute A(i)
        hmac.update(a);
        a = hmac.doFinal();
        hmac.reset();

        hmac.update(a);
        hmac.update(seed);
        byte[] digest = hmac.doFinal();
        System.arraycopy(digest, 0, buffer, 0, buffer.length);
        hmac.reset();

        idx = 0;
    }
}
