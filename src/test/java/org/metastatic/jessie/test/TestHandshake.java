package org.metastatic.jessie.test;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.metastatic.jessie.provider.*;

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
}
