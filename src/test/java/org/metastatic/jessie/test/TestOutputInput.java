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
import org.metastatic.jessie.SSLProtocolVersion;
import org.metastatic.jessie.provider.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.DataFormatException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

// See if InputSecurityParameters can read what OutputSecurityParameters writes.
public class TestOutputInput
{
    static final byte[] KEY_EXPANSION = new byte[]{107, 101, 121, 32, 101, 120, 112,
            97, 110, 115, 105, 111, 110};

    // This (and some other instances of setting up crypto algs) is a good case study
    // in one way we're WET vs. DRY (we love typing). We really could unify a lot of
    // this stuff into a sensible (testable!) API.

    @Test
    public void testTLS1CBC() throws Exception
    {
        CipherSuite suite = new CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA();
        ProtocolVersion version = ProtocolVersion.TLS_1;
        SessionImpl session = new SessionImpl();
        session.version = version;
        session.random = InsecureRandom.getInsecureRandom();
        byte[] masterSecret = new byte[48];
        Arrays.fill(masterSecret, (byte) 0xab);
        byte[] seed = new byte[KEY_EXPANSION.length + 56];
        Arrays.fill(seed, (byte) 0xcd);
        System.arraycopy(KEY_EXPANSION, 0, seed, 0, KEY_EXPANSION.length);

        KeyGenerator prf = new TestableKeyGenerator(new TLSPRFKeyGeneratorImpl(), new Jessie(), "TLS_PRF");
        prf.init(new TLSKeyGeneratorParameterSpec("TLS_PRF", seed, masterSecret, suite.keyLength(), suite.macLength(), suite.ivLength()));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();

        Cipher writeCipher = suite.cipher(version.protocolVersion());
        writeCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().name()),
                new IvParameterSpec(keys.getClientWriteIV()));
        Mac writeMac = suite.mac(version.protocolVersion());
        writeMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), writeMac.getAlgorithm()));
        OutputSecurityParameters out = new OutputSecurityParameters(writeCipher, writeMac, null, session, suite);

        Cipher readCipher = suite.cipher(version.protocolVersion());
        readCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().name()),
                new IvParameterSpec(keys.getClientWriteIV()));
        Mac readMac = suite.mac(version.protocolVersion());
        readMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), readMac.getAlgorithm()));
        InputSecurityParameters in = new InputSecurityParameters(readCipher, readMac, null, version, suite);

        runEncryptDecryptTest(out, in);
    }

    private void runEncryptDecryptTest(OutputSecurityParameters out, InputSecurityParameters in) throws DataFormatException, IllegalBlockSizeException, ShortBufferException, IOException
    {
        for (int i = 0; i < 1024; i++)
        {
            byte[] data1 = new byte[i];
            Arrays.fill(data1, (byte) i);
            ByteBuffer output = ByteBuffer.allocate(2048); // should be large enough
            out.encrypt(new ByteBuffer[]{ByteBuffer.wrap(data1)}, 0, 1, ContentType.APPLICATION_DATA, output);
            output.flip();
            Record record = new Record(output);
            //System.out.println("encrypted record: " + record);
            ByteBuffer decrypted = ByteBuffer.allocate(record.length());
            in.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
            decrypted.flip();
            assertEquals(i, decrypted.remaining());
            byte[] data2 = new byte[i];
            decrypted.get(data2);
            assertArrayEquals(data1, data2);
        }
    }

    @Test
    public void testTLS1_1CBC() throws Exception
    {
        CipherSuite suite = new CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA();
        ProtocolVersion version = ProtocolVersion.TLS_1_1;
        SessionImpl session = new SessionImpl();
        session.version = version;
        session.random = InsecureRandom.getInsecureRandom();
        byte[] masterSecret = new byte[48];
        Arrays.fill(masterSecret, (byte) 0xab);
        byte[] seed = new byte[KEY_EXPANSION.length + 56];
        Arrays.fill(seed, (byte) 0xcd);
        System.arraycopy(KEY_EXPANSION, 0, seed, 0, KEY_EXPANSION.length);

        KeyGenerator prf = new TestableKeyGenerator(new TLSPRFKeyGeneratorImpl(), new Jessie(), "TLS_PRF");
        prf.init(new TLSKeyGeneratorParameterSpec("TLS_PRF", seed, masterSecret, suite.keyLength(), suite.macLength(), 0));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();

        Cipher writeCipher = suite.cipher(version.protocolVersion());
        // Don't init the cipher, it gets inited on each encrypt, with a random IV.
        Mac writeMac = suite.mac(version.protocolVersion());
        writeMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), writeMac.getAlgorithm()));
        OutputSecurityParameters out = new OutputSecurityParameters(writeCipher, writeMac, null, session, suite,
                new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().name()));

        Cipher readCipher = suite.cipher(version.protocolVersion());
        Mac readMac = suite.mac(version.protocolVersion());
        readMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), readMac.getAlgorithm()));
        InputSecurityParameters in = new InputSecurityParameters(readCipher, readMac, null, version, suite,
                new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().name()));

        runEncryptDecryptTest(out, in);
    }

    @Test
    public void testTLS1_2GCM() throws Exception
    {
        CipherSuite suite = new CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256();
        ProtocolVersion version = ProtocolVersion.TLS_1_2;
        SessionImpl session = new SessionImpl();
        session.version = version;
        session.random = InsecureRandom.getInsecureRandom();

        byte[] masterSecret = new byte[48];
        Arrays.fill(masterSecret, (byte) 0xab);
        byte[] seed = new byte[KEY_EXPANSION.length + 56];
        Arrays.fill(seed, (byte) 0xcd);
        System.arraycopy(KEY_EXPANSION, 0, seed, 0, KEY_EXPANSION.length);

        KeyGenerator prf = new TestableKeyGenerator(new TLSKeyGenerators.TLSKeyGeneratorSHA256(), new Prov(), "P_SHA256");
        prf.init(new TLSKeyGeneratorParameterSpec("P_SHA256", seed, masterSecret, suite.keyLength(), 0, suite.ivLength()));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();

        Cipher writeCipher = suite.cipher(version.protocolVersion());
        // TODO the line below needs two things fixed, the algorithm name (not hardcoded "AES"), and the tag length.
        OutputSecurityParameters out = new OutputSecurityParameters(writeCipher, null, session, suite, new SecretKeySpec(keys.getClientWriteKey(), "AES"), keys.getClientWriteIV(), 128);

        Cipher readCipher = suite.cipher(version.protocolVersion());
        // TODO same here
        InputSecurityParameters in = new InputSecurityParameters(readCipher, null, version, suite, new SecretKeySpec(keys.getClientWriteKey(), "AES"), keys.getClientWriteIV(), 128);

        runEncryptDecryptTest(out, in);
    }

    static class Prov extends Provider
    {
        Prov()
        {
            super("test", 1.0, "test provider");
        }
    }
}
