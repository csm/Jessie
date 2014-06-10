/* TestPrivateCredentials.java
   Copyright (C) 2014 Casey Marshall

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

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.Test;
import org.metastatic.jessie.provider.*;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestHandshake {
    @Test
    public void testHelloRequest() throws Exception {
        byte[] bytes = Util.toByteArray("00000000");
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes), null, ProtocolVersion.TLS_1_2);
        assertEquals(Handshake.Type.HELLO_REQUEST, handshake.type());
        assertTrue(handshake.body() instanceof HelloRequest);
    }

    @Test
    public void testHelloRequestRecord() throws Exception {
        byte[] bytes = Util.toByteArray("160303000400000000");
        Record record = new Record(ByteBuffer.wrap(bytes));
        if (TestDebug.DEBUG)
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
        assertArrayEquals(new byte[]{0x73}, hello.sessionId());
        assertEquals(1, hello.cipherSuites().size());
        assertTrue(hello.cipherSuites().get(0) instanceof CipherSuite.TLS_NULL_WITH_NULL_NULL);
        assertEquals(1, hello.compressionMethods().size());
        assertEquals(CompressionMethod.NULL, hello.compressionMethods().get(0));
        if (TestDebug.DEBUG)
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
        if (TestDebug.DEBUG)
            System.out.printf("%s%n", handshake);
    }

    @Test
    public void testCertificate() throws Exception {
        byte[] bytes = Util.toByteArray("0b0003d8" +
                "0003d5" + // cert list length
                "0003d2" + // cert 1 length
                "308203ce308202b60209008ca2ce6aa8a4567a300d06092a864886f70d01010505003081a8310b3009060355040613025553311330110603550408130a43616c69666f726e6961311330110603550407130a53616e7461204372757a31163014060355040a130d4d6f64616c20446f6d61696e733110300e060355040b13074861636b696e67311730150603550403130e6d6574617374617469632e6f7267312c302a06092a864886f70d010901161d63617365792e6d61727368616c6c406d6574617374617469632e6f7267301e170d3134303533303230313834345a170d3135303533303230313834345a3081a8310b3009060355040613025553311330110603550408130a43616c69666f726e6961311330110603550407130a53616e7461204372757a31163014060355040a130d4d6f64616c20446f6d61696e733110300e060355040b13074861636b696e67311730150603550403130e6d6574617374617469632e6f7267312c302a06092a864886f70d010901161d63617365792e6d61727368616c6c406d6574617374617469632e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100adedc35b1cdbe149418758f10fac2b359cf3f77eb6dfa8db051638aaad29c62e2e8ad495159bd435c7a0936e1d5722477ae77b056d19f7cc5b850cb5a624c945ff65ab865da342fb98f7103b1e95d63acc47b50c3cf4cae1abfd62a36b44be09a53f38e0c46d36e0e2a65e29e61b100bc977fbf7a329ee6cc68bc5ab97afc3badf836f8a7db439a0cfefa724e544b74d10e5db253abc3bee9622fb01b0d727a0fb1c7be736ebbd13614748a7474f92866744e5526363dd2dba993d4992530bc49d01752aa3071a48f2c1b9c1595fa69808776130541030f60e10bc4e83a6fa302a049f5f1114a8a421ba17138b7e4e5a9638f3bc1515d82f70307739c5a211790203010001300d06092a864886f70d010105050003820101007debf0db825aacdf944a7ecfa1591b23a74d9da1eff4e8c767da9b09885163d57b0caa6b012fc1c27ed5de74c30bbfeb778fd76c7815797edc3ae5edca36f9611c8cfd7153da6484cceb6c48d1a9a2737997d0c8750ad29d293a11b637366e25f694137940589e205da293a8e0a82648ec1b01f3e127928276b380602b159c5d98d391f67a9eac8d6d9b2c6873d9bfba9720a94e36c516a9c959bbb07af3c20ff234eeeb859ea809475b84b0f0543808c36ac0b4e0d68a45f73218df0b53a0b919cc6c104ec7f64ec0e815eb64569b21318fefdb1ad2eff71b52dc2cfdbd13692baa3ea2d7206420a0f83921921ee85e7e0c44c543b5b8767c724fa4d9eaab82");
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes));
        assertEquals(Handshake.Type.CERTIFICATE, handshake.type());
        Handshake.Body body = handshake.body();
        assertTrue(body instanceof Certificate);
        Certificate cert = (Certificate) body;
        assertEquals(1, cert.certificates().size());
        if (TestDebug.DEBUG)
            System.out.println(handshake);
    }

    @Test
    public void testServerKeyExchangeDH() throws Exception {
        byte[] bytes = Util.toByteArray("0c00001f" +
                "000101" + // server DH p 3
                "000102" + // server DH g 3
                "000103" + // server DH y 3
                "00140000000000000000000000000000000000000000" // DSS signature, 2 + 20
        );
        Handshake handshake = new Handshake(ByteBuffer.wrap(bytes), new CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA(), ProtocolVersion.TLS_1_1);
        assertEquals(Handshake.Type.SERVER_KEY_EXCHANGE, handshake.type());
        Handshake.Body body = handshake.body();
        assertTrue(body instanceof ServerKeyExchange);
        ServerKeyExchange kex = (ServerKeyExchange) body;
        Object params = kex.params();
        assertTrue(params instanceof ServerDHParams);
        if (TestDebug.DEBUG)
            System.out.printf("%s%n", handshake);
    }
}
