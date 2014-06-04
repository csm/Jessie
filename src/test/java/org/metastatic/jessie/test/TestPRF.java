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

package org.metastatic.jessie.test;

import org.junit.Test;
import org.metastatic.jessie.provider.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertArrayEquals;

public class TestPRF
{
    Jessie jessie = new Jessie();

    @Test
    public void testTLS10() throws Exception
    {
        // Test vector from https://github.com/moserware/TLS-1.0-Analyzer/blob/master/UnitTests/Prf10Tests.cs
        byte[] secret = new byte[48];
        Arrays.fill(secret, (byte) 0xab);
        byte[] seed = new byte[64];
        Arrays.fill(seed, (byte) 0xcd);
        byte[] label = "PRF Testvector".getBytes();
        byte[] result = Util.toByteArray("D3D4D1E349B5D515044666D51DE32BAB258CB521B6B053463E354832FD976754443BCF9A296519BC289ABCBC1187E4EB" +
            "D31E602353776C408AAFB74CBC85EFF69255F9788FAA184CBB957A9819D84A5D7EB006EB459D3AE8DE9810454B8B2D8F1AFBC655A8C9A013");

        KeyGenerator gen = new TestableKeyGenerator(new TLSPRFKeyGeneratorImpl(), jessie, "TLS_PRF");
        gen.init(new TLSKeyGeneratorParameterSpec("TLS_PRF", Util.concat(label, seed), secret, 52, 0, 0));
        SecretKey key = gen.generateKey();
        System.out.println(Util.toHexString(key.getEncoded()));
        assertArrayEquals(result, key.getEncoded());
        TLSSessionKeys sessionKeys = (TLSSessionKeys) key;
        sessionKeys.getClientWriteIV();
        sessionKeys.getClientWriteKey();
        sessionKeys.getClientWriteMACKey();
        sessionKeys.getServerWriteIV();
        sessionKeys.getServerWriteKey();
        sessionKeys.getServerWriteMACKey();
    }

    @Test
    public void testSHA256() throws Exception
    {
        // Test vector from http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
        byte[] secret = Util.toByteArray("9bbe436ba940f017b17652849a71db35");
        byte[] seed = Util.toByteArray("a0ba9f936cda311827a6f796ffd5198c");
        byte[] label = "test label".getBytes();
        byte[] output = Util.toByteArray("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");

        KeyGenerator gen = new TestableKeyGenerator(new TLSKeyGenerators.TLSKeyGeneratorSHA256(), jessie, "P_SHA256");
        gen.init(new TLSKeyGeneratorParameterSpec("P_SHA256", Util.concat(label, seed), secret, 50, 0, 0));
        SecretKey key = gen.generateKey();
        System.out.println(Util.toHexString(key.getEncoded()));
        assertArrayEquals(output, key.getEncoded());
        TLSSessionKeys sessionKeys = (TLSSessionKeys) key;
        sessionKeys.getClientWriteIV();
        sessionKeys.getClientWriteKey();
        sessionKeys.getClientWriteMACKey();
        sessionKeys.getServerWriteIV();
        sessionKeys.getServerWriteKey();
        sessionKeys.getServerWriteMACKey();
    }
}
