/* PrivateCredentials.java -- private key/certificate pairs.
   Copyright (C) 2006, 2007  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

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


package org.metastatic.jessie;

import java.io.*;

import java.math.BigInteger;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.ManagerFactoryParameters;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import com.google.common.io.ByteStreams;

/**
 * An instance of a manager factory parameters for holding a single
 * certificate/private key pair, encoded in PEM format.
 */
public class PrivateCredentials implements ManagerFactoryParameters
{
    // Fields.
    // -------------------------------------------------------------------------

    public static final byte[] BEGIN_DSA = "-----BEGIN DSA PRIVATE KEY".getBytes();
    public static final byte[] BEGIN_RSA = "-----BEGIN RSA PRIVATE KEY".getBytes();

    private List<Entry> entries;

    private class Entry implements Destroyable
    {
        PrivateKey privateKey;
        final X509Certificate[] certChain;

        private Entry(PrivateKey privateKey, X509Certificate[] certChain)
        {
            this.privateKey = privateKey;
            this.certChain = certChain;
        }

        @Override
        public void destroy()
        {
            privateKey = null;
        }

        @Override
        public boolean isDestroyed()
        {
            return privateKey == null;
        }
    }

    // Constructor.
    // -------------------------------------------------------------------------

    public PrivateCredentials()
    {
        entries = new LinkedList<>();
    }

    // Instance methods.
    // -------------------------------------------------------------------------

    private CallbackHandler getCallbackHandler()
    {
        try
        {
            String className = System.getProperty("org.metastatic.jessie.passwordCallbackHandler");
            Class clazz = Class.forName(className);
            return (CallbackHandler) clazz.newInstance();
        }
        catch (ClassNotFoundException|InstantiationException|IllegalAccessException e)
        {
            return null;
        }
    }

    public void add(InputStream certChain, InputStream privateKey)
            throws CertificateException, InvalidKeyException, InvalidKeySpecException,
            IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedCallbackException, InvalidAlgorithmParameterException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = cf.generateCertificates(certChain);
        X509Certificate[] chain = certs.toArray(new X509Certificate[certs.size()]);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ByteStreams.copy(privateKey, bout);
        byte[] pkData = bout.toByteArray();

        String alg = null;
        outer:for (int i = 0; i < pkData.length - BEGIN_DSA.length; i++)
        {
            boolean isRsa = true;
            boolean isDsa = true;
            for (int j = 0; j < BEGIN_DSA.length; j++)
            {
                byte b = pkData[j + i];
                if (b != BEGIN_DSA[j])
                    isDsa = false;
                if (b != BEGIN_RSA[j])
                    isRsa = false;
                if (!isDsa && !isRsa)
                    continue outer;
            }
            if (isDsa)
            {
                alg = "DSA";
                break;
            }
            if (isRsa)
            {
                alg = "RSA";
                break;
            }
        }
        if (alg == null)
            throw new InvalidKeyException("unknown algorithm in PEM file");

        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(pkData);
        Cipher cipher = Cipher.getInstance(epki.getAlgName());
        CallbackHandler callbackHandler = getCallbackHandler();
        if (callbackHandler == null)
            throw new InvalidKeyException("no callback handler configured, can't get password for private key");
        PasswordCallback callback = new PasswordCallback("Password for private key", false);
        callbackHandler.handle(new Callback[] { callback });
        PBEKeySpec keySpec = new PBEKeySpec(callback.getPassword());
        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epki.getAlgName());
        Key key = skFactory.generateSecret(keySpec);
        AlgorithmParameters params = epki.getAlgParameters();
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        KeySpec spec = epki.getKeySpec(cipher);
        KeyFactory factory = KeyFactory.getInstance(alg);
        PrivateKey pk = factory.generatePrivate(spec);

        entries.add(new Entry(pk, chain));
    }

    public List<PrivateKey> getPrivateKeys()
    {
        return entries.stream().map(e -> e.privateKey).collect(Collectors.toList());
    }

    public List<X509Certificate[]> getCertChains()
    {
        return entries.stream().map(e -> e.certChain).collect(Collectors.toList());
    }

    public void destroy()
    {
        entries.stream().forEach(Entry::destroy);
    }

    public boolean isDestroyed()
    {
        return entries.stream().allMatch(Entry::isDestroyed);
    }
}
