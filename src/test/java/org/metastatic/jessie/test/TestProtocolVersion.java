package org.metastatic.jessie.test;

import java.io.ByteArrayInputStream;

import org.junit.Test;
import org.metastatic.jessie.provider.ProtocolVersion;
import org.metastatic.jessie.provider.Util;

import static org.junit.Assert.assertEquals;

/**
 * Copyright (C) 2013 Memeo, Inc.
 * All Rights Reserved
 */
public class TestProtocolVersion
{
    @Test
    public void testSSL3() throws Exception {
        byte[] bytes = Util.toByteArray("0300");
        ProtocolVersion version = ProtocolVersion.read(new ByteArrayInputStream(bytes));
        assertEquals(ProtocolVersion.SSL_3, version);
    }

    @Test
    public void testTLS1() throws Exception {
        byte[] bytes = Util.toByteArray("0301");
        ProtocolVersion version = ProtocolVersion.read(new ByteArrayInputStream(bytes));
        assertEquals(ProtocolVersion.TLS_1, version);
    }

    @Test
    public void testTLS1_1() throws Exception {
        byte[] bytes = Util.toByteArray("0302");
        ProtocolVersion version = ProtocolVersion.read(new ByteArrayInputStream(bytes));
        assertEquals(ProtocolVersion.TLS_1_1, version);
    }

    @Test
    public void testTLS1_2() throws Exception {
        byte[] bytes = Util.toByteArray("0303");
        ProtocolVersion version = ProtocolVersion.read(new ByteArrayInputStream(bytes));
        assertEquals(ProtocolVersion.TLS_1_2, version);
    }
}
