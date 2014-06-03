/* 
   Copyright (C) 2014  Casey Marshall

This file is a part of Jessie.

Jessie is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

Jessie is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Jessie; if not, write to the Free Software
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

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class TLSPRFKeyGeneratorImpl extends KeyGeneratorSpi
{
    private KeyGenerator md5gen, sha1gen;
    private int keyLength;
    private String algName;
    private int macLength;
    private int ivLength;

    public TLSPRFKeyGeneratorImpl() throws NoSuchAlgorithmException
    {
        md5gen = KeyGenerator.getInstance("P_MD5");
        sha1gen = KeyGenerator.getInstance("P_SHA1");
    }

    @Override
    protected void engineInit(SecureRandom secureRandom)
    {
        throw new IllegalArgumentException("must initialize with a TLSKeyGeneratorParameterSpec");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException
    {
        if (!(algorithmParameterSpec instanceof TLSKeyGeneratorParameterSpec))
            throw new InvalidAlgorithmParameterException("need a TLSKeyGeneratorParameterSpec");
        keyLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getKeyLength();
        macLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getMacLength();
        ivLength = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getIVLength();
        algName = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getAlgName();
        byte[] secret = ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getSecret();
        int l_s = (int) Math.ceil((double) secret.length / 2.0);
        byte[] md5secret = new byte[l_s];
        byte[] shasecret = new byte[l_s];
        System.arraycopy(secret, 0, md5secret, 0, l_s);
        System.arraycopy(secret, secret.length - l_s, shasecret, 0, l_s);
        md5gen.init(new TLSKeyGeneratorParameterSpec(((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getAlgName(),
                ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getSeed(),
                md5secret, keyLength, macLength, ivLength));
        sha1gen.init(new TLSKeyGeneratorParameterSpec(((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getAlgName(),
                ((TLSKeyGeneratorParameterSpec) algorithmParameterSpec).getSeed(),
                shasecret, keyLength, macLength, ivLength));
    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new IllegalArgumentException("must initialize with a TLSKeyGeneratorParameterSpec");
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        TLSSessionKeys md5key = (TLSSessionKeys) md5gen.generateKey();
        TLSSessionKeys shakey = (TLSSessionKeys) sha1gen.generateKey();
        return md5key.xor(shakey);
    }
}
