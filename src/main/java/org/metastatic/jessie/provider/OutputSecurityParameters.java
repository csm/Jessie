/* OutputSecurityParameters.java --
   Copyright (C) 2006  Free Software Foundation, Inc.

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


package org.metastatic.jessie.provider;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;

public class OutputSecurityParameters
{
    private static final Logger logger = Logger.getLogger(OutputSecurityParameters.class.getName());
    private final Cipher cipher;
    private final Mac mac;
    private final Deflater deflater;
    private final SessionImpl session;
    private final CipherSuite suite;
    private long sequence;

    private final SecretKey tls11CBCKey;

    private final SecretKey gcmKey;
    private final byte[] gcmSeed;
    private final int gcmTagLength;

    static final boolean enableCBCProtection;

    static
    {
        String enabled = Util.getProperty("jsse.enableCBCProtection");
        if (enabled == null)
            enableCBCProtection = true;
        else
            enableCBCProtection = Boolean.valueOf(enabled);
    }

    public OutputSecurityParameters(final Cipher cipher, final Mac mac,
                                    final Deflater deflater, SessionImpl session,
                                    CipherSuite suite)
    {
        this.cipher = cipher;
        this.mac = mac;
        this.deflater = deflater;
        this.session = session;
        this.suite = suite;
        sequence = 0;
        tls11CBCKey = null;
        gcmKey = null;
        gcmSeed = null;
        gcmTagLength = 0;
    }

    // Constructor for TLSv1.1+ CBC ciphers
    public OutputSecurityParameters(Cipher cipher, Mac mac, Deflater deflater, SessionImpl session, CipherSuite suite,
                                    SecretKey tls11CBCKey)
    {
        this.cipher = cipher;
        this.mac = mac;
        this.deflater = deflater;
        this.session = session;
        this.suite = suite;
        this.tls11CBCKey = tls11CBCKey;
        sequence = 0;
        gcmKey = null;
        gcmSeed = null;
        gcmTagLength = 0;
    }

    // Constructor for TLSv1.2+ GCM modes
    public OutputSecurityParameters(Cipher cipher, Deflater deflater, SessionImpl session, CipherSuite suite,
                                    SecretKey gcmKey, byte[] gcmSeed, int gcmTagLength)
    {
        this.cipher = cipher;
        this.deflater = deflater;
        this.session = session;
        this.suite = suite;
        this.gcmKey = gcmKey;
        this.gcmSeed = gcmSeed;
        this.gcmTagLength = gcmTagLength;
        sequence = 0;
        tls11CBCKey = null;
        mac = null;
    }

    /**
     * Encrypt a record, storing the result in the given output buffer.
     *
     * @return The number of bytes taken from the input, and the number stored
     * into `output;' that is, the size of the encrypted fragment, plus the
     * encoding for the record.
     */
    public int[] encrypt(final ByteBuffer[] input, int offset, int length,
                         final ContentType contentType, final ByteBuffer output)
            throws DataFormatException, IllegalBlockSizeException, ShortBufferException
    {
        if (offset < 0 || offset >= input.length
                || length <= 0 || offset + length > input.length)
            throw new IndexOutOfBoundsException();

        if (Debug.DEBUG)
            for (int i = offset; i < offset + length; i++)
                logger.log(Level.FINE, "encrypting record [{0}]: {1}",
                        new Object[]{i - offset, input[i]});

        int maclen = 0;
        if (mac != null)
            maclen = session.isTruncatedMac() ? 10 : mac.getMacLength();
        if (suite.cipherAlgorithm() == CipherAlgorithm.AES_GCM)
            maclen = gcmTagLength / 8;

        int ivlen = 0;
        byte[] iv = null;
        if (session.version.compareTo(ProtocolVersion.TLS_1_1) >= 0
                && !suite.isStreamCipher())
        {
            ivlen = cipher.getBlockSize();
            iv = new byte[ivlen];
            session.random().nextBytes(iv);
        }
        if (suite.cipherAlgorithm() == CipherAlgorithm.AES_GCM)
        {
            ivlen = 8;
            iv = new byte[ivlen];
            session.random().nextBytes(iv);
            //System.out.println("GCM nonce: " + Util.toHexString(iv, ':'));
        }

        int padaddlen = 0;
        if (!suite.isStreamCipher()
            && session.version.compareTo(ProtocolVersion.TLS_1) >= 0)
        {
            padaddlen = (session.random().nextInt(255 / cipher.getBlockSize())
                    * cipher.getBlockSize());
        }

        int fragmentLength = 0;
        int tlsCompressedLength = 0;
        ByteBuffer[] fragments = null;
        // Compress the content, if needed.
        if (deflater != null)
        {
            ByteArrayOutputStream deflated = new ByteArrayOutputStream();

            byte[] inbuf = new byte[1024];
            byte[] outbuf = new byte[1024];
            int written = 0;

            // Here we use the guarantee that the deflater won't increase the
            // output size by more than 1K -- we resign ourselves to only deflate
            // as much data as we have space for *uncompressed*,
            int limit = output.remaining() - (maclen + ivlen + padaddlen) - 1024;

            for (int i = offset; i < length && written < limit; i++)
            {
                ByteBuffer in = input[i];
                while (in.hasRemaining() && written < limit)
                {
                    int l = Math.min(in.remaining(), inbuf.length);
                    l = Math.min(limit - written, l);
                    in.get(inbuf, 0, l);
                    deflater.setInput(inbuf, 0, l);
                    l = deflater.deflate(outbuf);
                    deflated.write(outbuf, 0, l);
                    written += l;
                }
            }
            deflater.finish();
            while (!deflater.finished())
            {
                int l = deflater.deflate(outbuf);
                deflated.write(outbuf, 0, l);
                written += l;
            }
            fragments = new ByteBuffer[]{ ByteBuffer.wrap(deflated.toByteArray()) };
            tlsCompressedLength = ((int) deflater.getBytesWritten());
            fragmentLength = tlsCompressedLength + maclen + ivlen;
            deflater.reset();
            offset = 0;
            length = 1;
        }
        else
        {
            int limit = output.remaining() - (maclen + ivlen + padaddlen);
            fragments = input;
            for (int i = offset; i < length && fragmentLength < limit; i++)
            {
                int l = Math.min(limit - fragmentLength, fragments[i].remaining());
                fragmentLength += l;
            }
            tlsCompressedLength = fragmentLength;
            fragmentLength += maclen + ivlen;
        }

        // Compute padding...
        int padlen = 0;
        byte[] pad = null;
        if (!suite.isStreamCipher())
        {
            int bs = cipher.getBlockSize();
            padlen = bs - (fragmentLength % bs);
            if (Debug.DEBUG)
                logger.log(Level.FINE,
                           "framentLen:{0} padlen:{1} blocksize:{2}",
                           new Object[] { fragmentLength, padlen, bs });
            // TLS 1.0 and later uses a random amount of padding, up to
            // 255 bytes. Each byte of the pad is equal to the padding
            // length, minus one.
            padlen += padaddlen;
            while (padlen > 255)
                padlen -= bs;
            pad = new byte[padlen];
            for (int i = 0; i < padlen; i++)
                pad[i] = (byte) (padlen - 1);
            fragmentLength += pad.length;
        }

        // If there is a MAC, compute it.
        byte[] macValue = null;
        if (mac != null)
        {
            ByteBuffer authenticator = InputSecurityParameters.authenticator(sequence, contentType, session.version,
                    (short) tlsCompressedLength);
            mac.update(authenticator);
            int written = 0;
            for (int i = offset; i < length && written < fragmentLength; i++)
            {
                ByteBuffer fragment = fragments[i].duplicate();
                int l = Math.min(fragment.remaining(), fragmentLength - written);
                fragment.limit(fragment.position() + l);
                mac.update(fragment);
            }
            macValue = mac.doFinal();
        }

        if (Debug.DEBUG_ENCRYPTION)
            logger.log(Level.INFO, "TLSCompressed.length:{0} fragmentLength:{1} macLen:{2} padlen:{3} mac:{4} pad:{5}",
                       new Object[] { tlsCompressedLength, fragmentLength, maclen, padlen,
                               macValue != null ? Util.toHexString(macValue) : "(none)",
                               pad != null ? Util.toHexString(pad) : "(none)" });

        Record outrecord = new Record(output);
        outrecord.setContentType(contentType);
        outrecord.setVersion(session.version);
        outrecord.setLength(fragmentLength);

        int consumed = 0;
        ByteBuffer outfragment = outrecord.fragment();

        if (cipher != null)
        {
            if (iv != null)
            {
                if (suite.cipherAlgorithm() == CipherAlgorithm.AES_GCM)
                {
                    byte[] ivValue = new byte[gcmSeed.length + iv.length];
                    System.arraycopy(gcmSeed, 0, ivValue, 0, gcmSeed.length);
                    System.arraycopy(iv, 0, ivValue, gcmSeed.length, iv.length);

                    try
                    {
                        cipher.init(Cipher.ENCRYPT_MODE, gcmKey, new GCMParameterSpec(gcmTagLength, ivValue));
                    }
                    catch (InvalidKeyException | InvalidAlgorithmParameterException e)
                    {
                        throw new IllegalArgumentException(e);
                    }
                    ByteBuffer aad = InputSecurityParameters.authenticator(sequence, contentType, session.version,
                            (short) tlsCompressedLength);
                    //System.out.println("GCM AAD: " + Util.hexDump(aad));
                    cipher.updateAAD(aad);
                    outfragment.put(iv);
                }
                else // CBC, explicit IV
                {
                    try
                    {
                        cipher.init(Cipher.ENCRYPT_MODE, tls11CBCKey, new IvParameterSpec(iv));
                    }
                    catch (InvalidKeyException | InvalidAlgorithmParameterException e)
                    {
                        // We don't expect this to happen.
                        throw new IllegalArgumentException(e);
                    }
                    outfragment.put(iv);
                }
            }
            int toWrite = fragmentLength - maclen - ivlen - padlen;
            for (int i = offset; i < offset + length && consumed < toWrite; i++)
            {
                ByteBuffer fragment = fragments[i].slice();
                int l = Math.min(fragment.remaining(), toWrite - consumed);
                fragment.limit(fragment.position() + l);
                cipher.update(fragment, outfragment);
                fragments[i].position(fragments[i].position() + l);
                consumed += l;
            }
            if (macValue != null)
                cipher.update(ByteBuffer.wrap(macValue), outfragment);
            if (pad != null)
                cipher.update(ByteBuffer.wrap(pad), outfragment);
            if (session.version.compareTo(ProtocolVersion.TLS_1) > 0)
            {
                try
                {
                    cipher.doFinal(ByteBuffer.wrap(new byte[0]), outfragment);
                }
                catch (BadPaddingException e)
                {
                    // Shouldn't happen. We are encrypting.
                    throw new IllegalArgumentException(e);
                }
            }
        }
        else
        {
            // iv and pad are only used if we have a block cipher.
            int toWrite = fragmentLength - maclen;
            for (int i = offset; i < offset + length && consumed < toWrite; i++)
            {
                ByteBuffer fragment = fragments[i];
                int l = Math.min(fragment.remaining(), toWrite - consumed);
                fragment.limit(fragment.position() + l);
                outfragment.put(fragment);
                consumed += l;
            }
            if (macValue != null)
                outfragment.put(macValue);
        }

        // Advance the output buffer's position.
        output.position(output.position() + outrecord.length() + 5);
        sequence++;

        return new int[]{consumed, fragmentLength + 5};
    }

    CipherSuite suite()
    {
        return suite;
    }

    boolean needToSplitPayload()
    {
        return (session.version.compareTo(ProtocolVersion.TLS_1_1) < 0 &&
                suite.isCBCMode() && enableCBCProtection);
    }

}
