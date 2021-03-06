/* SecurityParameters.java -- SSL security parameters.
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

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class InputSecurityParameters
{
    private static final Logger logger = Logger.getLogger(InputSecurityParameters.class.getName());
    private final Cipher cipher;
    private final Mac mac;
    private final Inflater inflater;
    private final ProtocolVersion version;
    private final CipherSuite suite;
    private long sequence;

    private final SecretKey tls11SecretKey;

    private final SecretKey gcmSecretKey;
    private final int gcmTagLength;
    private final byte[] gcmSalt;

    public InputSecurityParameters(final Cipher cipher, final Mac mac,
                                   final Inflater inflater,
                                   final ProtocolVersion version,
                                   final CipherSuite suite)
    {
        this.cipher = cipher;
        this.mac = mac;
        this.inflater = inflater;
        this.version = version;
        this.suite = suite;
        sequence = 0;
        tls11SecretKey = null;
        gcmSecretKey = null;
        gcmTagLength = 0;
        gcmSalt = null;
    }

    public InputSecurityParameters(final Cipher cipher, final Mac mac,
                                   final Inflater inflater, final ProtocolVersion version,
                                   final CipherSuite suite, final SecretKey tls11SecretKey)
    {
        this.cipher = cipher;
        this.mac = mac;
        this.inflater = inflater;
        this.version = version;
        this.suite = suite;
        this.tls11SecretKey = tls11SecretKey;
        sequence = 0;
        gcmSalt = null;
        gcmSecretKey = null;
        gcmTagLength = 0;
    }

    public InputSecurityParameters(final Cipher cipher, final Inflater inflater,
                                   final ProtocolVersion version, final CipherSuite suite,
                                   final SecretKey gcmSecretKey, final byte[] gcmSalt,
                                   final int gcmTagLength)
    {
        this.cipher = cipher;
        this.mac = null;
        this.inflater = inflater;
        this.version = version;
        this.suite = suite;
        tls11SecretKey = null;
        this.gcmSalt = gcmSalt.clone();
        this.gcmSecretKey = gcmSecretKey;
        this.gcmTagLength = gcmTagLength;
        sequence = 0;
    }

    /**
     * Decrypt a record, storing the decrypted fragment into the given array
     * of byte buffers.
     *
     * @param record The input record.
     * @param output The output buffers.
     * @param offset The offset of the first buffer to use.
     * @param length The number of buffers to use.
     * @return The number of bytes put in the output buffers.
     * @throws DataFormatException       If decompression fails.
     * @throws IllegalBlockSizeException If the current cipher is a block cipher,
     *                                   and the input fragment is not a multiple of the block size.
     * @throws MacException              If verifying the MAC fails.
     * @throws SSLException              ???
     * @throws ShortBufferException
     */
    public int decrypt(Record record, ByteBuffer[] output, int offset, int length)
            throws DataFormatException, IllegalBlockSizeException,
            IOException, ShortBufferException
    {
        return decrypt(record, output, offset, length, null);
    }

    /**
     * Decrypt a record, storing the decrypted fragment into the given growable
     * buffer.
     *
     * @param record       The input record.
     * @param outputStream The output buffer.
     * @return The number of bytes put into the output buffer.
     * @throws DataFormatException
     * @throws IllegalBlockSizeException
     * @throws MacException
     * @throws SSLException
     * @throws ShortBufferException
     */
    public int decrypt(Record record, OutputStream outputStream)
            throws DataFormatException, IllegalBlockSizeException,
            IOException, ShortBufferException
    {
        return decrypt(record, null, 0, 0, outputStream);
    }

    private int decrypt(Record record, ByteBuffer[] output, int offset, int length,
                        OutputStream outputStream)
            throws DataFormatException, IllegalBlockSizeException,
            IOException, ShortBufferException
    {
        boolean badPadding = false;
        ByteBuffer fragment;

        byte[] iv = new byte[0];
        int ivlen = 0;
        if (cipher != null)
        {
            if (suite.cipherAlgorithm() == CipherAlgorithm.AES_GCM)
            {
                if (version.compareTo(ProtocolVersion.TLS_1_2) < 0)
                    throw new SSLException("got AEAD ciphersuite with version < TLSv1.2");
                ByteBuffer input = record.fragment();
                byte[] ivBytes = new byte[12]; // FIXME this could be different, this is for AES/GCM suites
                System.arraycopy(gcmSalt, 0, ivBytes, 0, gcmSalt.length);
                input.get(ivBytes, gcmSalt.length, ivBytes.length - gcmSalt.length);
                if (Debug.DEBUG_DECRYPTION)
                    logger.log(Level.INFO, "AEAD ivBytes:{0}, record.length:{1} input.remaining:{2}",
                            new Object[] { Util.toHexString(ivBytes, ':'), record.length(), input.remaining() });
                try
                {
                    GCMParameterSpec nextParameterSpec = new GCMParameterSpec(gcmTagLength, ivBytes);
                    cipher.init(Cipher.DECRYPT_MODE, gcmSecretKey, nextParameterSpec);
                }
                catch (InvalidAlgorithmParameterException | InvalidKeyException e)
                {
                    throw new SSLException(e);
                }
                ByteBuffer aadBuffer = authenticator(sequence, record.contentType(), record.version(),
                        (short) (input.remaining() - (gcmTagLength / 8)));
                if (Debug.DEBUG_DECRYPTION)
                    logger.log(Level.INFO, "GCM AAD:\n{0}", Util.hexDump(aadBuffer));
                cipher.updateAAD(aadBuffer);
                fragment = ByteBuffer.allocate(input.remaining() - (gcmTagLength / 8));
                try
                {
                    cipher.doFinal(input, fragment);
                    fragment.flip();
                }
                catch (BadPaddingException e)
                {
                    if (Debug.DEBUG)
                        logger.log(Level.INFO, "AEAD decryption failed", e);
                    badPadding = true;
                }
            }
            else
            {
                ByteBuffer input = record.fragment();
                if (!suite.isStreamCipher() && version.compareTo(ProtocolVersion.TLS_1_1) >= 0)
                {
                    ivlen = cipher.getBlockSize();
                    iv = new byte[ivlen];
                    input.get(iv);
                    try
                    {
                        cipher.init(Cipher.DECRYPT_MODE, tls11SecretKey, new IvParameterSpec(iv));
                    }
                    catch (InvalidKeyException | InvalidAlgorithmParameterException e)
                    {
                        throw new SSLException(e);
                    }
                }
                fragment = ByteBuffer.allocate(input.remaining());
                cipher.update(input, fragment);
                fragment.flip();
            }
        }
        else
        {
            fragment = record.fragment();
        }

        if (Debug.DEBUG_DECRYPTION)
            logger.log(Level.INFO, "decrypted fragment:\n{0}",
                    Util.hexDump((ByteBuffer) fragment.duplicate().position(0), " >> "));

        int fragmentLength = fragment.remaining();
        int padlen = 0;
        int padRemoveLen = 0;
        if (!suite.isStreamCipher())
        {
            padlen = fragment.get(fragmentLength - 1) & 0xFF;
            padRemoveLen = padlen + 1;
            if (Debug.DEBUG)
                logger.log(Level.FINE, "padlen:{0}", padlen);

            // In TLSv1 and later, the padding must be `padlen' copies of the
            // value `padlen'.
            // Here we compare all bytes leading up to the padding, up to
            // 256 bytes, to try and foil timing attacks.
            badPadding = checkPadding(fragmentLength, fragment, padlen);

            if (Debug.DEBUG)
                logger.log(Level.FINE, "padding bad? {0}",
                        badPadding);
            if (!badPadding)
                fragmentLength = fragmentLength - padRemoveLen;
        }

        // Compute and check the MAC.

        int maclen = 0;
        if (mac != null)
        {
            maclen = mac.getMacLength();
            fragmentLength -= maclen;
            ByteBuffer auth = authenticator(sequence, record.getContentType(),
                    record.version(), (short) (fragmentLength));
            //System.out.println("authenticator: " + Util.hexDump(auth));
            mac.update(auth);
            /*mac.update((byte) (sequence >>> 56));
            mac.update((byte) (sequence >>> 48));
            mac.update((byte) (sequence >>> 40));
            mac.update((byte) (sequence >>> 32));
            mac.update((byte) (sequence >>> 24));
            mac.update((byte) (sequence >>> 16));
            mac.update((byte) (sequence >>> 8));
            mac.update((byte) sequence);
            mac.update((byte) record.getContentType().getValue());
            ProtocolVersion version = record.version();
            mac.update((byte) version.major());
            mac.update((byte) version.minor());
            mac.update((byte) ((fragmentLength) >>> 8));
            mac.update((byte) (fragmentLength));*/
            ByteBuffer content =
                    (ByteBuffer) fragment.duplicate().limit(fragmentLength);
            //System.out.printf("length: %d, content to MAC:%n%s%n", fragmentLength, Util.hexDump(content));
            mac.update(content);
            byte[] mac1 = mac.doFinal();

            // Run the MAC over the rest of the padding, too.
            ByteBuffer paddingBuffer = (ByteBuffer) fragment.duplicate().position(fragmentLength);
            mac.update(paddingBuffer);
            byte[] x = mac.doFinal();

            byte[] mac2 = new byte[mac.getMacLength()];
            mac.reset();
            ((ByteBuffer) fragment.duplicate().position(fragmentLength)).get(mac2);
            if (Debug.DEBUG)
                logger.log(Level.FINE, "mac1:{0} mac2:{1}",
                        new Object[]{Util.toHexString(mac1, ':'), Util.toHexString(mac2, ':')});
            if (!MessageDigest.isEqual(mac1, mac2))
                badPadding = true;
        }

        // We always say "bad MAC" and not "bad padding," because saying
        // the latter will leak information to an attacker.
        if (badPadding)
            throw new MacException();

        // Inflate the compressed bytes.
        int produced = 0;
        if (inflater != null)
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream(fragmentLength);
            byte[] inbuffer = new byte[1024];
            byte[] outbuffer = new byte[1024];
            boolean done = false;
            fragment.limit(fragmentLength);

            while (!done)
            {
                int l;
                if (inflater.needsInput())
                {
                    l = Math.min(inbuffer.length, fragment.remaining());
                    fragment.get(inbuffer, 0, l);
                    inflater.setInput(inbuffer);
                }

                l = inflater.inflate(outbuffer);
                out.write(outbuffer, 0, l);
                done = !fragment.hasRemaining() && inflater.finished();
            }

            ByteBuffer outbuf = ByteBuffer.wrap(out.toByteArray());
            if (outputStream != null)
            {
                byte[] buf = new byte[1024];
                while (outbuf.hasRemaining())
                {
                    int l = Math.min(outbuf.remaining(), buf.length);
                    outbuf.get(buf, 0, l);
                    outputStream.write(buf, 0, l);
                    produced += l;
                }
            }
            else
            {
                int i = offset;
                while (outbuf.hasRemaining() && i < offset + length)
                {
                    int l = Math.min(output[i].remaining(), outbuf.remaining());
                    ByteBuffer b = (ByteBuffer)
                            outbuf.duplicate().limit(outbuf.position() + l);
                    output[i++].put(b);
                    outbuf.position(outbuf.position() + l);
                    produced += l;
                }
                if (outbuf.hasRemaining())
                    throw new BufferOverflowException();
            }
        }
        else
        {
            ByteBuffer outbuf = (ByteBuffer)
                    fragment.duplicate().position(0).limit(fragmentLength);
            if (outputStream != null)
            {
                byte[] buf = new byte[1024];
                while (outbuf.hasRemaining())
                {
                    int l = Math.min(outbuf.remaining(), buf.length);
                    outbuf.get(buf, 0, l);
                    outputStream.write(buf, 0, l);
                    produced += l;
                }
            }
            else
            {
                int i = offset;
                while (outbuf.hasRemaining() && i < offset + length)
                {
                    int l = Math.min(output[i].remaining(), outbuf.remaining());
                    ByteBuffer b = (ByteBuffer) outbuf.duplicate().limit(outbuf.position() + l);
                    output[i++].put(b);
                    outbuf.position(outbuf.position() + l);
                    produced += l;
                }
                if (outbuf.hasRemaining())
                    throw new BufferOverflowException();
            }
        }

        sequence++;

        return produced;
    }

    public static boolean checkPadding(int recordLength, ByteBuffer fragment, int padlen)
    {
        int good = 0;
        int totalLength = Math.min(256, recordLength);
        byte[] mask = paddingMask(totalLength, padlen);
        byte[] pad = new byte[totalLength];
        ((ByteBuffer) fragment.duplicate().position(recordLength - totalLength)).get(pad);
        //System.out.printf("%02x%n%s%n%s%n", padlen, Util.toHexString(pad), Util.toHexString(mask));
        for (int i = 0; i < pad.length; i++)
            good |= (mask[i] & 0xFF) & (padlen ^ (pad[i] & 0xFF));
        if (Debug.DEBUG)
            logger.log(Level.FINE, "TLSv1.x padding\n{0}",
                    Util.toHexString(pad));
        return good != 0;
    }

    CipherSuite cipherSuite()
    {
        return suite;
    }

    /**
     * Generate a padding mask.
     *
     * @param padlen
     * @return
     */
    private static byte[] paddingMask(int totalLength, int padlen)
    {
        if (padlen > totalLength)
            padlen = totalLength;
        byte[] mask = new byte[totalLength];
        int i;
        for (i = 0; i < totalLength - padlen - 1; i++)
            mask[i] = 0x00;
        for (; i < totalLength; i++)
            mask[i] = (byte) 0xFF;
        return mask;
    }

    static ByteBuffer authenticator(long sequence, ContentType type,
                                    ProtocolVersion version, short fragmentLength)
    {
        ByteBuffer buffer = ByteBuffer.allocate(8 + 1 + 2 + 2);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(sequence);
        buffer.put((byte) type.getValue());
        buffer.put(version.getEncoded());
        buffer.putShort(fragmentLength);
        buffer.flip();
        return buffer;
    }
}
