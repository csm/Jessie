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

import org.bouncycastle.openssl.PEMReader;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.ManagerFactoryParameters;
import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An instance of a manager factory parameters for holding a single
 * certificate/private key pair, encoded in PEM format.
 */
public class PrivateCredentials implements ManagerFactoryParameters
{
    // Fields.
    // -------------------------------------------------------------------------

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
            System.out.println("callback class name: " + className);
            Class clazz = Class.forName(className);
            System.out.println("callback class: " + clazz);
            return (CallbackHandler) clazz.newInstance();
        }
        catch (ClassNotFoundException|InstantiationException|IllegalAccessException e)
        {
            e.printStackTrace();
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

        CallbackHandler callbackHandler = getCallbackHandler();
        if (callbackHandler == null)
            throw new InvalidKeyException("no callback handler configured, can't get password for private key");
        PasswordCallback callback = new PasswordCallback("Password for private key", false);
        callbackHandler.handle(new Callback[] { callback });
        PEMReader pemReader = new PEMReader(new InputStreamReader(privateKey), () -> {
            try
            {
                callbackHandler.handle(new Callback[]{ callback });
                return callback.getPassword();
            }
            catch (IOException | UnsupportedCallbackException e)
            {
                return new char[0];
            }
        });
        Object o = pemReader.readObject();

        PrivateKey pk = null;
        if (o instanceof PrivateKey)
            pk = (PrivateKey) o;
        else if (o instanceof KeyPair)
            pk = ((KeyPair) o).getPrivate();
        else
            throw new InvalidKeyException("was expecting a key pair or private key");

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
