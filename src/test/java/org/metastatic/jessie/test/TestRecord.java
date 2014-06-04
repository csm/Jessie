package org.metastatic.jessie.test;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.metastatic.jessie.provider.ContentType;
import org.metastatic.jessie.provider.ProtocolVersion;
import org.metastatic.jessie.provider.Record;
import org.metastatic.jessie.provider.Util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Copyright (C) 2013 Memeo, Inc.
 * All Rights Reserved
 */
public class TestRecord
{
    @Test
    public void testEmptyRecord() throws Exception
    {
        byte[] bytes = Util.toByteArray("1703030000");
        Record record = new Record(ByteBuffer.wrap(bytes));
        System.out.println(record);
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        assertEquals(ProtocolVersion.TLS_1_2, record.version());
        assertEquals(0, record.length());
    }

    @Test
    public void testUnderflow() throws Exception
    {
        byte[] bytes = Util.toByteArray("170303000500010203");
        try {
            Record record = new Record(ByteBuffer.wrap(bytes));
            record.fragment();
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
    }
}
