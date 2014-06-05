package org.metastatic.jessie.test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.Test;
import org.metastatic.jessie.provider.*;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Copyright (C) 2013 Memeo, Inc.
 * All Rights Reserved
 */
public class TestHandshake
{
    @Test
    public void testHelloRequest() throws Exception
    {
        byte[] bytes = Util.toByteArray("00000000");
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes), null, ProtocolVersion.TLS_1_2);
        assertEquals(Handshake.Type.HELLO_REQUEST, handshake.type());
        assertTrue(handshake.body() instanceof HelloRequest);
    }

    @Test
    public void testHelloRequestRecord() throws Exception {
        byte[] bytes = Util.toByteArray("160303000400000000");
        Record record = new Record(ByteBuffer.wrap(bytes));
        System.out.println(record);
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        assertEquals(ProtocolVersion.TLS_1_2, record.version());
        assertEquals(4, record.length());
        Handshake handshake = new Handshake(record.fragment(), null, record.version());
        assertEquals(Handshake.Type.HELLO_REQUEST, handshake.type());
        assertEquals(0, handshake.length());
        assertTrue(handshake.body() instanceof HelloRequest);
    }

    @Test
    public void testClientHello() throws Exception {
        byte[] bytes = Util.toByteArray("0100002a" +
                "0303" + // client version 2
                "0102030472727272727272727272727272727272727272727272727272727272" + // client random 32
                "0173" + // session id 2
                "00020000" + // cipher suites 4
                "0100" // compression methods 2
        );
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes));
        assertEquals(Handshake.Type.CLIENT_HELLO, handshake.type());
        Handshake.Body body = handshake.body();
        assertTrue(body instanceof ClientHello);
        ClientHello hello = (ClientHello) body;
        assertEquals(ProtocolVersion.TLS_1_2, hello.version());
        assertEquals(16909060, hello.random().gmtUnixTime());
        byte[] x = new byte[28];
        Arrays.fill(x, (byte) 0x72);
        assertArrayEquals(x, hello.random().randomBytes());
        assertArrayEquals(new byte[] { 0x73 }, hello.sessionId());
        assertEquals(1, hello.cipherSuites().size());
        assertTrue(hello.cipherSuites().get(0) instanceof CipherSuite.TLS_NULL_WITH_NULL_NULL);
        assertEquals(1, hello.compressionMethods().size());
        assertEquals(CompressionMethod.NULL, hello.compressionMethods().get(0));
        System.out.printf("%s%n", handshake);
    }

    @Test
    public void testServerHello() throws Exception {
        byte[] bytes = Util.toByteArray("02000027" +
                "0303" + // server version 2
                "0506070852525252525252525252525252525252525252525252525252525252" + // server random 32
                "0153" + // session id 2
                "0000" + // cipher suite 2
                "00" // compression method 1
        );
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes));
        assertEquals(Handshake.Type.SERVER_HELLO, handshake.type());
        Handshake.Body body = handshake.body();
        assertTrue(body instanceof ServerHello);
        ServerHello hello = (ServerHello) body;
        assertEquals(ProtocolVersion.TLS_1_2, hello.version());
        assertEquals(84281096, hello.random().gmtUnixTime());
        byte[] b = new byte[28];
        Arrays.fill(b, (byte) 0x52);
        assertArrayEquals(b, hello.random().randomBytes());
        assertArrayEquals(new byte[]{0x53}, hello.sessionId());
        assertTrue(hello.cipherSuite() instanceof CipherSuite.TLS_NULL_WITH_NULL_NULL);
        assertEquals(CompressionMethod.NULL, hello.compressionMethod());
        System.out.printf("%s%n", handshake);
    }
}
