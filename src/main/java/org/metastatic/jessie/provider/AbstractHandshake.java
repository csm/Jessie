/* AbstractHandshake.java -- abstract handshake handler.
   Copyright (C) 2006  Free Software Foundation, Inc.
   Copyright (C) 2014  Casey Marshall

This file is a part of Jessie, and is derived from GNU Classpath.

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

import org.metastatic.jessie.SSLProtocolVersion;

import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * The base interface for handshake implementations. Concrete
 * subclasses of this class (one for the server, one for the client)
 * handle the HANDSHAKE content-type in communications.
 */
public abstract class AbstractHandshake
{
    protected static final Logger logger = Logger.getLogger(AbstractHandshake.class.getName());

    /**
     * "server finished" -- TLS 1.0 and later
     */
    protected static final byte[] SERVER_FINISHED
            = new byte[]{
            115, 101, 114, 118, 101, 114, 32, 102, 105, 110, 105, 115,
            104, 101, 100
    };

    /**
     * "client finished" -- TLS 1.0 and later
     */
    protected static final byte[] CLIENT_FINISHED
            = new byte[]{
            99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115,
            104, 101, 100
    };

    /**
     * "key expansion" -- TLS 1.0 and later
     */
    private static final byte[] KEY_EXPANSION =
            new byte[]{107, 101, 121, 32, 101, 120, 112,
                    97, 110, 115, 105, 111, 110};

    /**
     * "master secret" -- TLS 1.0 and later
     */
    private static final byte[] MASTER_SECRET
            = new byte[]{
            109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116
    };

    /**
     * "client write key" -- TLS 1.0 exportable whitener.
     */
    private static final byte[] CLIENT_WRITE_KEY
            = new byte[]{
            99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32, 107,
            101, 121
    };

    /**
     * "server write key" -- TLS 1.0 exportable whitener.
     */
    private static final byte[] SERVER_WRITE_KEY
            = new byte[]{
            115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32, 107,
            101, 121
    };

    private static final byte[] IV_BLOCK
            = new byte[]{
            73, 86, 32, 98, 108, 111, 99, 107
    };

    /**
     * SSL 3.0; the string "CLNT"
     */
    private static final byte[] SENDER_CLIENT
            = new byte[]{0x43, 0x4C, 0x4E, 0x54};

    /**
     * SSL 3.0; the string "SRVR"
     */
    private static final byte[] SENDER_SERVER
            = new byte[]{0x53, 0x52, 0x56, 0x52};

    /**
     * The currently-read handshake messages. There may be zero, or
     * multiple, handshake messages in this buffer.
     */
    protected ByteBuffer handshakeBuffer;

    /**
     * The offset into `handshakeBuffer' where the first unread
     * handshake message resides.
     */
    protected int handshakeOffset;

    protected MessageDigest sha;
    protected MessageDigest md5;
    protected MessageDigest sha256;

    protected final SSLEngineImpl engine;
    protected KeyAgreement keyAgreement;
    protected byte[] preMasterSecret;
    protected InputSecurityParameters inParams;
    protected OutputSecurityParameters outParams;
    protected LinkedList<DelegatedTask> tasks;
    protected Random serverRandom;
    protected Random clientRandom;
    protected CompressionMethod compression;

    protected AbstractHandshake(SSLEngineImpl engine)
            throws NoSuchAlgorithmException
    {
        this.engine = engine;
        sha = MessageDigest.getInstance("SHA-1");
        md5 = MessageDigest.getInstance("MD5");
        sha256 = MessageDigest.getInstance("SHA256");
        tasks = new LinkedList<>();
    }

    /**
     * Handles the next input message in the handshake. This is called
     * in response to a call to {@link javax.net.ssl.SSLEngine#unwrap}
     * for a message with content-type HANDSHAKE.
     *
     * @param fragment The input record. The callee should not assume that
     *                 the record's buffer is writable, and should not try to use it for
     *                 output or temporary storage.
     * @return An {@link SSLEngineResult} describing the result.
     */
    public final HandshakeStatus handleInput(ByteBuffer fragment)
            throws SSLException
    {
        if (!tasks.isEmpty())
            return HandshakeStatus.NEED_TASK;

        HandshakeStatus status = status();
        if (status != HandshakeStatus.NEED_UNWRAP)
            return status;

        // Try to read another...
        if (!pollHandshake(fragment))
            return HandshakeStatus.NEED_UNWRAP;

        while (hasMessage() && status != HandshakeStatus.NEED_WRAP)
        {
            int pos = handshakeOffset;
            status = implHandleInput();
            int len = handshakeOffset - pos;
            if (len == 0)
            {
                // Don't bother; the impl is just telling us to go around
                // again.
                continue;
            }
            if (doHash())
            {
                if (Debug.DEBUG)
                    logger.log(Level.FINE, "hashing output\n{0}", Util.wrapBuffer((ByteBuffer) handshakeBuffer
                            .duplicate().position(pos)
                            .limit(pos + len), " >> "));
                sha.update((ByteBuffer) handshakeBuffer.duplicate()
                        .position(pos).limit(pos + len));
                md5.update((ByteBuffer) handshakeBuffer.duplicate()
                        .position(pos).limit(pos + len));
            }
        }
        return status;
    }

    /**
     * Called to process more handshake data. This method will be called
     * repeatedly while there is remaining handshake data, and while the
     * status is
     *
     * @return
     * @throws SSLException
     */
    protected abstract HandshakeStatus implHandleInput()
            throws SSLException;

    /**
     * Produce more handshake output. This is called in response to a
     * call to {@link javax.net.ssl.SSLEngine#wrap}, when the handshake
     * is still in progress.
     *
     * @param fragment The output record; the callee should put its output
     *                 handshake message (or a part of it) in the argument's
     *                 <code>fragment</code>, and should set the record length
     *                 appropriately.
     * @return An {@link SSLEngineResult} describing the result.
     */
    public final HandshakeStatus handleOutput(ByteBuffer fragment)
            throws SSLException
    {
        if (!tasks.isEmpty())
            return HandshakeStatus.NEED_TASK;

        int orig = fragment.position();
        SSLEngineResult.HandshakeStatus status = implHandleOutput(fragment);
        if (doHash())
        {
            if (Debug.DEBUG)
                logger.log(Level.FINE, "hashing output:\n{0}",
                        Util.wrapBuffer((ByteBuffer) fragment.duplicate().flip().position(orig), " >> "));
            sha.update((ByteBuffer) fragment.duplicate().flip().position(orig));
            md5.update((ByteBuffer) fragment.duplicate().flip().position(orig));
        }
        return status;
    }

    /**
     * Called to implement the underlying output handling. The callee should
     * attempt to fill the given buffer as much as it can; this can include
     * multiple, and even partial, handshake messages.
     *
     * @param fragment The buffer the callee should write handshake messages to.
     * @return The new status of the handshake.
     * @throws SSLException If an error occurs processing the output message.
     */
    protected abstract SSLEngineResult.HandshakeStatus implHandleOutput(ByteBuffer fragment)
            throws SSLException;

    /**
     * Return a new instance of input security parameters, initialized with
     * the session key. It is, of course, only valid to invoke this method
     * once the handshake is complete, and the session keys established.
     * <p/>
     * <p>In the presence of a well-behaving peer, this should be called once
     * the <code>ChangeCipherSpec</code> message is recieved.
     *
     * @return The input parameters for the newly established session.
     * @throws SSLException If the handshake is not complete.
     */
    final InputSecurityParameters getInputParams() throws SSLException
    {
        checkKeyExchange();
        return inParams;
    }

    /**
     * Return a new instance of output security parameters, initialized with
     * the session key. This should be called after the
     * <code>ChangeCipherSpec</code> message is sent to the peer.
     *
     * @return The output parameters for the newly established session.
     * @throws SSLException If the handshake is not complete.
     */
    final OutputSecurityParameters getOutputParams() throws SSLException
    {
        checkKeyExchange();
        return outParams;
    }

    /**
     * Fetch a delegated task waiting to run, if any.
     *
     * @return The task.
     */
    final Runnable getTask()
    {
        if (tasks.isEmpty())
            return null;
        return tasks.removeFirst();
    }

    /**
     * Used by the skeletal code to query the current status of the handshake.
     * This <em>should</em> be the same value as returned by the previous call
     * to {@link #implHandleOutput(ByteBuffer)} or {@link #implHandleInput()}.
     *
     * @return The current handshake status.
     */
    abstract HandshakeStatus status();

    /**
     * Check if the key exchange completed successfully, throwing an exception
     * if not.
     * <p/>
     * <p>Note that we assume that the caller of our SSLEngine is correct, and
     * that they did run the delegated tasks that encapsulate the key exchange.
     * What we are primarily checking, therefore, is that no error occurred in the
     * key exchange operation itself.
     *
     * @throws SSLException If the key exchange did not complete successfully.
     */
    abstract void checkKeyExchange() throws SSLException;

    /**
     * Handle an SSLv2 client hello. This is only used by SSL servers.
     *
     * @param hello The hello message.
     */
    abstract void handleV2Hello(ByteBuffer hello) throws SSLException;

    /**
     * Attempt to read the next handshake message from the given
     * record. If only a partial handshake message is available, then
     * this method saves the incoming bytes and returns false. If a
     * complete handshake is read, or if there was one buffered in the
     * handshake buffer, this method returns true, and `handshakeBuffer'
     * can be used to read the handshake.
     *
     * @param fragment The input record.
     * @return True if a complete handshake is present in the buffer;
     * false if only a partial one.
     */
    protected boolean pollHandshake(final ByteBuffer fragment)
    {
        // Allocate space for the new fragment.
        if (handshakeBuffer == null
                || handshakeBuffer.remaining() < fragment.remaining())
        {
            // We need space for anything still unread in the handshake
            // buffer...
            int len = ((handshakeBuffer == null) ? 0
                    : handshakeBuffer.position() - handshakeOffset);

            // Plus room for the incoming record.
            len += fragment.remaining();
            reallocateBuffer(len);
        }

        if (Debug.DEBUG)
            logger.log(Level.FINE, "inserting {0} into {1}",
                       new Object[] { fragment, handshakeBuffer });

        // Put the fragment into the buffer.
        handshakeBuffer.put(fragment);

        return hasMessage();
    }

    protected boolean doHash()
    {
        return true;
    }

    /**
     * Tell if the handshake buffer currently has a full handshake
     * message.
     */
    protected boolean hasMessage()
    {
        if (handshakeBuffer == null)
            return false;
        ByteBuffer tmp = handshakeBuffer.duplicate();
        tmp.flip();
        tmp.position(handshakeOffset);
        if (Debug.DEBUG)
            logger.log(Level.FINE, "current buffer: {0}; test buffer {1}",
                       new Object[] { handshakeBuffer, tmp });
        if (tmp.remaining() < 4)
            return false;
        Handshake handshake = new Handshake(tmp.slice());
        if (Debug.DEBUG)
            logger.log(Level.FINE, "handshake len:{0} remaining:{1}",
                       new Object[] { handshake.length(), tmp.remaining() });
        return (handshake.length() <= tmp.remaining() - 4);
    }

    /**
     * Reallocate the handshake buffer so it can hold `totalLen'
     * bytes. The smallest buffer allocated is 1024 bytes, and the size
     * doubles from there until the buffer is sufficiently large.
     */
    private void reallocateBuffer(final int totalLen)
    {
        int len = handshakeBuffer == null ? -1
                : handshakeBuffer.capacity() - (handshakeBuffer.limit() - handshakeOffset);
        if (len >= totalLen)
        {
            // Big enough; no need to reallocate; but maybe shift the contents
            // down.
            if (handshakeOffset > 0)
            {
                handshakeBuffer.flip().position(handshakeOffset);
                handshakeBuffer.compact();
                handshakeOffset = 0;
            }
            return;
        }

        // Start at 1K (probably the system's page size). Double the size
        // from there.
        len = 1024;
        while (len < totalLen)
            len = len << 1;
        ByteBuffer newBuf = ByteBuffer.allocate(len);

        // Copy the unread bytes from the old buffer.
        if (handshakeBuffer != null)
        {
            handshakeBuffer.flip();
            handshakeBuffer.position(handshakeOffset);
            newBuf.put(handshakeBuffer);
        }
        handshakeBuffer = newBuf;

        // We just put only unread handshake messages in the new buffer;
        // the offset of the next one is now zero.
        handshakeOffset = 0;
    }

    /**
     * Generate the session keys from the computed master secret.
     *
     * @param clientRandom The client's nonce.
     * @param serverRandom The server's nonce.
     * @param session      The session being established.
     * @return The derived keys.
     */
    protected TLSSessionKeys generateKeys(Random clientRandom, Random serverRandom,
                                          SessionImpl session) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        int maclen = 0;
        switch (session.suite.macAlgorithm())
        {
            case MD5:
                maclen = 16;
                break;
            case SHA:
                maclen = 20;
                break;
            case SHA256:
                maclen = 32;
                break;
        }
        int ivlen = 0;
        switch (session.suite.cipherAlgorithm())
        {
            case DES:
            case DESede:
                ivlen = 8;
                break;
            case AES:
                ivlen = 16;
                break;
            default:
                ivlen = 0;
        }
        int keylen = session.suite.keyLength();

        KeyGenerator prf = session.suite.prf(session.version.protocolVersion());
        byte[] seed = new byte[KEY_EXPANSION.length
                + clientRandom.length()
                + serverRandom.length()];
        System.arraycopy(KEY_EXPANSION, 0, seed, 0, KEY_EXPANSION.length);
        serverRandom.buffer().get(seed, KEY_EXPANSION.length,
                serverRandom.length());
        clientRandom.buffer().get(seed, (KEY_EXPANSION.length
                        + serverRandom.length()),
                clientRandom.length()
        );
        prf.init(new TLSKeyGeneratorParameterSpec("TLS_PRF", seed, session.privateData.masterSecret,
                 keylen, maclen, ivlen));

        TLSSessionKeys sessionKeys = (TLSSessionKeys) prf.generateKey();

        if (Debug.DEBUG_KEY_EXCHANGE)
            logger.log(Level.FINE,
                    "keys generated;\n  [0]: {0}\n  [1]: {1}\n  [2]: {2}\n" +
                            "  [3]: {3}\n  [4]: {4}\n  [5]: {5}",
                    new Object[] {
                        Util.toHexString(sessionKeys.getClientWriteMACKey(), ':'),
                        Util.toHexString(sessionKeys.getServerWriteMACKey(), ':'),
                        Util.toHexString(sessionKeys.getClientWriteKey(), ':'),
                        Util.toHexString(sessionKeys.getServerWriteKey(), ':'),
                        Util.toHexString(sessionKeys.getClientWriteIV(), ':'),
                        Util.toHexString(sessionKeys.getServerWriteIV(), ':')}
            );
        return sessionKeys;
    }

    /**
     * Generate a "finished" message. The hashes passed in are modified
     * by this function, so they should be clone copies of the digest if
     * the hash function needs to be used more.
     *
     * @param handshakeHashes      The hashes of the handshake messages.
     * @param isClient Whether or not the client-side finished message is
     *                 being computed.
     * @param session  The current session.
     * @return A byte buffer containing the computed finished message.
     */
    protected ByteBuffer generateFinished(MessageDigest[] handshakeHashes,
                                          boolean isClient,
                                          SessionImpl session)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        ByteBuffer finishedBuffer = null;
        finishedBuffer = ByteBuffer.allocate(12);
        KeyGenerator prf;
        if (session.version == ProtocolVersion.TLS_1_2)
            prf = KeyGenerator.getInstance("P_SHA256");
        else
            prf = KeyGenerator.getInstance("TLS_PRF");
        List<byte[]> hashes = Arrays.asList(handshakeHashes).stream().map(h -> h.digest()).collect(Collectors.toList());
        if (Debug.DEBUG)
            logger.log(Level.FINE, "finished md5:{0} sha:{1}",
                    hashes.stream().map(Util::toHexString).collect(Collectors.toList()).toArray());

        int seedLen = CLIENT_FINISHED.length + hashes.stream().mapToInt(b -> b.length).sum();
        ByteArrayOutputStream bout = new ByteArrayOutputStream(seedLen);
        if (isClient)
            bout.write(CLIENT_FINISHED, 0, CLIENT_FINISHED.length);
        else
            bout.write(SERVER_FINISHED, 0, SERVER_FINISHED.length);
        hashes.forEach(h -> bout.write(h, 0, h.length));
        byte[] seed = bout.toByteArray();
        prf.init(new TLSKeyGeneratorParameterSpec(prf.getAlgorithm(), seed, session.privateData.masterSecret,
                6, 0, 0));
        byte[] finishedValue = prf.generateKey().getEncoded();
        finishedBuffer.put(finishedValue).position(0);
        return finishedBuffer;
    }

    protected void initDiffieHellman(DHPrivateKey dhKey, SecureRandom random)
            throws SSLException
    {
        try
        {
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(dhKey, random);
        } catch (InvalidKeyException ike)
        {
            throw new SSLException(ike);
        } catch (NoSuchAlgorithmException nsae)
        {
            throw new SSLException(nsae);
        }
    }

    protected void generateMasterSecret(Random clientRandom,
                                        Random serverRandom,
                                        SessionImpl session)
            throws SSLException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        assert (clientRandom != null);
        assert (serverRandom != null);
        assert (session != null);

        if (Debug.DEBUG_KEY_EXCHANGE)
            logger.log(Level.FINE, "preMasterSecret:\n{0}",
                    Util.toHexString(preMasterSecret));

        byte[] seed = new byte[clientRandom.length()
                + serverRandom.length()
                + MASTER_SECRET.length];
        System.arraycopy(MASTER_SECRET, 0, seed, 0, MASTER_SECRET.length);
        clientRandom.buffer().get(seed, MASTER_SECRET.length,
                clientRandom.length());
        serverRandom.buffer().get(seed,
                MASTER_SECRET.length + clientRandom.length(),
                serverRandom.length());
        KeyGenerator prf;
        if (session.version == ProtocolVersion.TLS_1_2)
            prf = KeyGenerator.getInstance("P_SHA256");
        else
            prf = KeyGenerator.getInstance("TLS_PRF");
        prf.init(new TLSKeyGeneratorParameterSpec(prf.getAlgorithm(), seed, preMasterSecret,
                48 / 2, 0, 0));
        TLSSessionKeys masterSecret = (TLSSessionKeys) prf.generateKey();
        session.privateData.masterSecret = masterSecret.getEncoded();

        if (Debug.DEBUG_KEY_EXCHANGE)
            logger.log(Level.INFO, "master_secret: {0}",
                       Util.toHexString(session.privateData.masterSecret));

        // Wipe out the preMasterSecret.
        Arrays.fill(preMasterSecret, (byte) 0);
    }

    protected void setupSecurityParameters(TLSSessionKeys keys, boolean isClient,
                                           SSLEngineImpl engine,
                                           CompressionMethod compression)
            throws SSLException
    {
        assert (engine != null);
        assert (compression != null);

        try
        {
            CipherSuite s = engine.session().suite;
            final SSLProtocolVersion protocolVersion = engine.session().version.protocolVersion();
            Cipher inCipher = s.cipher(protocolVersion);
            Mac inMac = s.mac(protocolVersion);
            Inflater inflater = (compression == CompressionMethod.ZLIB
                    ? new Inflater() : null);
            inCipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(isClient ? keys.getServerWriteKey() : keys.getClientWriteKey(),
                            s.cipherAlgorithm().toString()),
                    new IvParameterSpec(isClient ? keys.getServerWriteIV() : keys.getClientWriteIV())
            );
            inMac.init(new SecretKeySpec(isClient ? keys.getServerWriteMACKey() : keys.getClientWriteMACKey(),
                    inMac.getAlgorithm()));
            inParams = new InputSecurityParameters(inCipher, inMac,
                    inflater,
                    engine.session().version, s);

            Cipher outCipher = s.cipher(protocolVersion);
            Mac outMac = s.mac(protocolVersion);
            Deflater deflater = (compression == CompressionMethod.ZLIB
                    ? new Deflater() : null);
            outCipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(isClient ? keys.getClientWriteKey() : keys.getServerWriteKey(),
                            s.cipherAlgorithm().toString()),
                    new IvParameterSpec(isClient ? keys.getClientWriteIV() : keys.getServerWriteIV())
            );
            outMac.init(new SecretKeySpec(isClient ? keys.getClientWriteMACKey() : keys.getServerWriteMACKey(),
                    outMac.getAlgorithm()));
            outParams = new OutputSecurityParameters(outCipher, outMac,
                    deflater,
                    engine.session(), s);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException iape)
        {
            throw new SSLException(iape);
        }
    }

    protected void generatePSKSecret(String identity, byte[] otherkey,
                                     boolean isClient)
            throws SSLException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        SecretKey key = null;
        try
        {
            key = engine.contextImpl.pskManager.getKey(identity);
        } catch (KeyManagementException kme)
        {
        }
        if (key != null)
        {
            byte[] keyb = key.getEncoded();
            if (otherkey == null)
            {
                otherkey = new byte[keyb.length];
            }
            preMasterSecret = new byte[otherkey.length + keyb.length + 4];
            preMasterSecret[0] = (byte) (otherkey.length >>> 8);
            preMasterSecret[1] = (byte) otherkey.length;
            System.arraycopy(otherkey, 0, preMasterSecret, 2, otherkey.length);
            preMasterSecret[otherkey.length + 2]
                    = (byte) (keyb.length >>> 8);
            preMasterSecret[otherkey.length + 3]
                    = (byte) keyb.length;
            System.arraycopy(keyb, 0, preMasterSecret,
                    otherkey.length + 4, keyb.length);
        } else
        {
            // Generate a random, fake secret.
            preMasterSecret = new byte[8];
            preMasterSecret[1] = 2;
            preMasterSecret[5] = 2;
            preMasterSecret[6] = (byte) engine.session().random().nextInt();
            preMasterSecret[7] = (byte) engine.session().random().nextInt();
        }

        if (Debug.DEBUG_KEY_EXCHANGE)
            logger.log(Level.FINE, "PSK identity {0} key {1}",
                    new Object[]{identity, key});

        generateMasterSecret(clientRandom, serverRandom,
                engine.session());
        TLSSessionKeys keys = generateKeys(clientRandom, serverRandom,
                engine.session());
        setupSecurityParameters(keys, isClient, engine, compression);
    }

    protected class DHPhase extends DelegatedTask
    {
        private final DHPublicKey key;
        private final boolean full;

        protected DHPhase(DHPublicKey key)
        {
            this(key, true);
        }

        protected DHPhase(DHPublicKey key, boolean full)
        {
            this.key = key;
            this.full = full;
        }

        protected void implRun() throws InvalidKeyException, SSLException
        {
            keyAgreement.doPhase(key, true);
            preMasterSecret = keyAgreement.generateSecret();
            if (full)
            {
                try {
                    generateMasterSecret(clientRandom, serverRandom, engine.session());
                    TLSSessionKeys keys = generateKeys(clientRandom, serverRandom, engine.session());
                    setupSecurityParameters(keys, engine.getUseClientMode(), engine, compression);
                } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
                    throw new SSLException(e);
                }
            }
        }
    }

    protected class CertVerifier extends DelegatedTask
    {
        private final boolean clientSide;
        private final X509Certificate[] chain;
        private boolean verified;

        protected CertVerifier(boolean clientSide, X509Certificate[] chain)
        {
            this.clientSide = clientSide;
            this.chain = chain;
        }

        boolean verified()
        {
            return verified;
        }

        protected void implRun()
        {
            X509TrustManager tm = engine.contextImpl.trustManager;
            if (clientSide)
            {
                try
                {
                    tm.checkServerTrusted(chain, null);
                    verified = true;
                } catch (CertificateException ce)
                {
                    if (Debug.DEBUG)
                        logger.log(Level.INFO, "cert verify", ce);
                    // For client connections, ask the user if the certificate is OK.
                    /*
                    CallbackHandler verify = new DefaultCallbackHandler();
                    GetSecurityPropertyAction gspa
                            = new GetSecurityPropertyAction("jessie.certificate.handler");
                    String clazz = AccessController.doPrivileged(gspa);
                    try
                    {
                        ClassLoader cl =
                                AccessController.doPrivileged(new PrivilegedExceptionAction<ClassLoader>()
                                {
                                    public ClassLoader run() throws Exception
                                    {
                                        return ClassLoader.getSystemClassLoader();
                                    }
                                });
                        verify = (CallbackHandler) cl.loadClass(clazz).newInstance();
                    } catch (Exception x)
                    {
                        // Ignore.
                        if (Debug.DEBUG)
                            logger.log(Component.SSL_DELEGATED_TASK,
                                    "callback handler loading", x);
                    }
                    // XXX Internationalize
                    CertificateCallback confirm =
                            new CertificateCallback(chain[0],
                                    "The server's certificate could not be verified. There is no proof " +
                                            "that this server is who it claims to be, or that their certificate " +
                                            "is valid. Do you wish to continue connecting? "
                            );

                    try
                    {
                        verify.handle(new Callback[]{confirm});
                        verified = confirm.getSelectedIndex() == ConfirmationCallback.YES;
                    } catch (Exception x)
                    {
                        if (Debug.DEBUG)
                            logger.log(Component.SSL_DELEGATED_TASK,
                                    "callback handler exception", x);
                        verified = false;
                    }*/
                }
            } else
            {
                try
                {
                    tm.checkClientTrusted(chain, null);
                } catch (CertificateException ce)
                {
                    verified = false;
                }
            }

            if (verified)
                engine.session().setPeerVerified(true);
        }
    }

    protected class DHE_PSKGen extends DelegatedTask
    {
        private final DHPublicKey dhKey;
        private final SecretKey psKey;
        private final boolean isClient;

        protected DHE_PSKGen(DHPublicKey dhKey, SecretKey psKey, boolean isClient)
        {
            this.dhKey = dhKey;
            this.psKey = psKey;
            this.isClient = isClient;
        }

        /* (non-Javadoc)
         * @see gnu.javax.net.ssl.provider.DelegatedTask#implRun()
         */
        @Override
        protected void implRun() throws Throwable
        {
            keyAgreement.doPhase(dhKey, true);
            byte[] dhSecret = keyAgreement.generateSecret();
            byte[] psSecret = null;
            if (psKey != null)
                psSecret = psKey.getEncoded();
            else
            {
                psSecret = new byte[8];
                engine.session().random().nextBytes(psSecret);
            }

            preMasterSecret = new byte[dhSecret.length + psSecret.length + 4];
            preMasterSecret[0] = (byte) (dhSecret.length >>> 8);
            preMasterSecret[1] = (byte) dhSecret.length;
            System.arraycopy(dhSecret, 0, preMasterSecret, 2, dhSecret.length);
            preMasterSecret[dhSecret.length + 2] = (byte) (psSecret.length >>> 8);
            preMasterSecret[dhSecret.length + 3] = (byte) psSecret.length;
            System.arraycopy(psSecret, 0, preMasterSecret, dhSecret.length + 4,
                    psSecret.length);

            generateMasterSecret(clientRandom, serverRandom, engine.session());
            TLSSessionKeys keys = generateKeys(clientRandom, serverRandom, engine.session());
            setupSecurityParameters(keys, isClient, engine, compression);
        }
    }
}
