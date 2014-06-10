package org.metastatic.jessie.test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

import org.junit.Test;
import org.metastatic.jessie.provider.*;

import static org.junit.Assert.assertEquals;

/**
 */
public class TestSampleSessionAES_CBC_TLS1_1
{
    // C=`openssl ciphers | tr : '' | grep AES | tr '' :`
    // openssl -cipher $C -tls1_1 -connect developer.google.com:443

    /*
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1.1
    Cipher    : ECDHE-RSA-AES128-SHA
    Session-ID: 2C105B7727B7E672C67B610283FDEA7617A1CFED0E226EF9EF7D89508BF0A1A4
    Session-ID-ctx:
    Master-Key: EA4EDF69688C4B7AA0D0D62D692CEEAC9DD5C2486531524400426B67D5B3F555970817FD4065C55F313716C96A31E618
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 100800 (seconds)
    TLS session ticket:
    0000 - 7e b3 8f 34 1a 3a 4c 1d-d3 ab 59 52 f3 ee 59 50   ~..4.:L...YR..YP
    0010 - d0 60 af 1a b5 87 b7 7c-b9 3c 10 9a b6 66 de bd   .`.....|.<...f..
    0020 - c3 6f 59 5f a7 cb 76 85-7e 67 dd c3 03 d4 a6 15   .oY_..v.~g......
    0030 - b0 ef 17 ef 23 2c 27 0f-1d cb de 20 ae e4 85 54   ....#,'.... ...T
    0040 - fe b9 8d e4 b2 25 40 9a-2e d4 ad 13 2c 66 ba b0   .....%@.....,f..
    0050 - 27 f4 b8 2d 0b fe 3c 5a-59 07 aa f3 1b 30 0b 44   '..-..<ZY....0.D
    0060 - c4 d6 80 aa 41 5d 83 be-ac 87 75 30 80 4b d3 c9   ....A]....u0.K..
    0070 - be 0d 74 cf 38 3f 28 10-1e 1f 95 76 21 3d a7 a3   ..t.8?(....v!=..
    0080 - e5 91 f5 5a 8d 09 b1 e6-54 03 0f 8d 7a 47 d3 a0   ...Z....T...zG..
    0090 - d8 ec b7 d2 1c 5b 82 7e-29 33 b3 05 be 19 50 ab   .....[.~)3....P.
    00a0 - 61 6f 8e bf                                       ao..

    Start Time: 1402369903
    Timeout   : 7200 (sec)
    Verify return code: 20 (unable to get local issuer certificate)
     */

    @Test
    public void test() throws Exception {
        byte[] masterSecret = Util.toByteArray("EA4EDF69688C4B7AA0D0D62D692CEEAC9DD5C2486531524400426B67D5B3F555970817FD4065C55F313716C96A31E618");
        byte[] clientHelloBytes = Util.toByteArray(
                "160301009d010000990302c97d6d591ddb39649f04d2fc8469a226e5d683" +
                "d1e6bafbbf8afc79858fc5047e000026c014c00ac022c02100390038c00f" +
                "c0050035c013c009c01fc01e00330032c00ec004002f00ff020100004900" +
                "0b000403000102000a00340032000e000d0019000b000c00180009000a00" +
                "160017000800060007001400150004000500120013000100020003000f00" +
                "10001100230000000f000101");
        byte[] serverHelloBytes = Util.toByteArray(
                "160302003d0200003903025396776fb76dc2c81b088632cef3ef51f1a593" +
                "d4c8d87a4f1d5e7e2b768c99b200c013000011ff01000100000b00040300" +
                "010200230000");
        byte[] clientFinishedBytes = Util.toByteArray(
                "1603020040254aec5fb8d8f7e79dc6e69ba7578542a258911f2073406454" +
                "66e565c516cde507e3ece8b141e393b01f28f905ce3f73d8ad4a1e9debd8" +
                "044aa639be6d34f11a");
        byte[] serverFinishedBytes = Util.toByteArray(
                "1603020040f201d83285918e28a607caa93e0c2c4396c93751863e912a1b" +
                "94e9502ea1a2d1593ad9a46cd89108fb7a2ee63606929a061ceb2be8a8ad" +
                "cad68384a6f023f3ba");
        byte[] clientAppBytes1 = Util.toByteArray(
                "17030200407111ce5e62ae31ecc041db2b68fe6ea336f4a024684eefb8a7" +
                "a36d4e903cfdcd2b3c1f2b6de5593afec848862521aa993b8c06790022a0" +
                "857c94cbddd7e71d12");
        byte[] clientAppBytes2 = Util.toByteArray(
                "1703020030057d88d976539fbeefa28c1c4d1283ba5d7d0b504ae7bddf33" +
                "f018beaf77920bc782c9247a8ffc1b3982e9595b2fb734");
        byte[] serverAppBytes1 = Util.toByteArray(
                "1703020580c545a44c631f0f1e40140aceb849ce253e2d326bcaa0aa3c72" +
                "794cbb48af6802cbad6cb01ea8f509314ceb099cb14750f1330382f77762" +
                "507d5a9d6789f155bea5147eca388e55520f215b755425a8384864edf563" +
                "f60d9a4af97cb55c8563954b96e2ad7e1a737bcf2dd2017afc78f4fba5bb" +
                "8a6081d843d0d002253d99214043c8a922dd77a433b77786e9055d46f36b" +
                "86b673dd9118bc30903a738071b77827adaaf71a865241f6b499c69ce1bf" +
                "7966106d35b9672110c582d72ec39f4cfc5a747ff1f931a7385958d82533" +
                "e806d9aac095c694b5e61110cb97b1ca122555daa606373e297eae27b34f" +
                "8483e9027f8744403f547e5787933b7aa38574d88ddff5b5f4947e08b587" +
                "f2c7664046a557318250d5b7f7575ae81088ed09a08afc01214c9b26060e" +
                "539404e56573b583422f15c687af5579db43f1bafa3b391aaebe97baa56b" +
                "53dbf7be592cffa697cce7e19e2018150882dcb061892a020b071c97b263" +
                "74029fc5891eda914f10e5ff8ea7e37ece04cfd4e78e046a092673368d28" +
                "42629b6b848b997c6297d83f4c1b9b33f5d3e6febf3da55d56ad1799d032" +
                "ef4c208f0b691f636fdd6be7f0a3de6147f778a464c26c26026016c0dbfd" +
                "5e6aefae0edb9e32ce935293ca1259c86715b4bb752b32485eaff965c385" +
                "14e999e9422d0352ff58cb978d988c9aaaa06cad7a6470f323af0c36e52f" +
                "9e2a99b5b213499814a5f9d97fa582b387d8f223fef3cb035bb346c4189e" +
                "2413b322fa05ea47ead826ba8d54157eefdbd3dfadebfa335e44adbedb45" +
                "9f3b9e03d565ffcc3d5a05e49e318714710cea1ae10212a677f12dc302e7" +
                "adb6bdcfb1127a67fd54271e34e3d48f5c5fc6a263e26656225ba663d818" +
                "e3acdd0b3d5b0ce95379d7997d192a877454d020940168448c0670627220" +
                "b7890dc2ef291708c9c435ed83643740cd97852b00e0799c58abb9f6cf7e" +
                "6a433c292355f102cb6949caa77d7cdb5cd4deeed0e03c20b6947d5de0cd" +
                "e572cc2079fa8b12ac1336f3f5526f01c14a7e05e20e49b924ec6ab192f0" +
                "3615904d0e357e2c689bb7aeea4732a3e3e0cf0663a870b5b2e70310370d" +
                "518195e589d235a13e56c8a398a1dab33f8feaf719ab7abe02b917d25386" +
                "cbce9b5a83ba4fb1391bc424ff70d61f85de4d44dbe26b884e2e0d996047" +
                "037e1f46d6663c662b858f76a74467afc30db8ce5d9e8fbef2ea94e2f373" +
                "147830b5a9eca7e369acfa5765d1e9fe6b00dde55e665eb61403c579c76f" +
                "157dae7bae279d4427e0e2922df0f874d9d0ffbc6dcd49de9d2afb687e19" +
                "e11f06501f7df5b7424ffe35f732684fb45874e08a6bb9a7e6f394ce1c2e" +
                "6359ecdc8dfad72ac3b07c5ec0f35bb4718cef1f710271a8b52764c12f24" +
                "c11cde0bf60645e4307946a7ea923d319f541524a5e41febdb2996663168" +
                "fe3a6fd30afd32946a8340415aeb17ddedf3cbe4772835883a024917e56b" +
                "31f36b43fb25f799f17ac1ae6fc6d8c178105e3ad4f554d0c15acf3c0bc1" +
                "b53c7913910d4a60ca7eb016c45b1ff49e30ac49f669f53ed67defeb00c3" +
                "02fbde118a20f6885c4935a0b12f405fe9f0145803e1b06a7c086eaf2668" +
                "8fa4867f1630dd2473aaf52934c62b68425daae42fdd43bc97abc3afd7d6" +
                "36c4359563e1e4cd1018a42c30f62bb66eebaffabe59ae764e3c84c7d502" +
                "b125585e6d7acf6fb51e49f211a4c5adaf56e2dfd215932bc8a64bb257bc" +
                "0083a283f3a72327824b8eaf1d849f3621c1e2e6de5e40a065bcc0fd35f0" +
                "b782cdfd6df3a5c38e73f543ab03493e56c15b6316ecc2a279df78a2be37" +
                "7c9a24fe8fe9e32c211aa2a65dfb218c52f28beb3138788975c6853f6da1" +
                "05f160f0ab104b9db66ed9c657d41296fd56f729cfa5180e57ef887e574a" +
                "5e4750c2204f01f6057cea42503288347cc1836c6235f66f98751b5c4adb" +
                "cea530c0d05c671a8d6d9b42bceb389f347aa84e2197435896d36df73041" +
                "9dcc05");
        byte[] serverAppBytes2 = Util.toByteArray(
                "17030200f096c58a80331d6807f061fe2a9a7aab82655c4209d35da821f3" +
                "21a68892edb3188081dadf143534279e1e3b6ba775015d43d3695f320746" +
                "2aae05f4b745613e4d99a8153efb708a69250a4e3ced6c8219ae3b8eabe2" +
                "60face266bbbb0111c6cb5bdf852910e8720485b5777bcb7f61838cbe8f7" +
                "c4b9ee7c987dbf31fc02a96c8c095eda8cca9639c40d0305b5575607a74b" +
                "bf2013e2b607adfead885ef8a98ebf8a4033b367562f49b91bf918433f4b" +
                "cca1a0276615f725a0ab1335c08bca0d18720af4deb929302b387d8ea733" +
                "99c8d312f7dfb6eee07a0be1f272bc95b9eb32b9529990e8029d5b6e6ea5" +
                "9be7fdcbda");
        byte[] clientAlertBytes = Util.toByteArray(
                "1503020030f61f3c11fa4f597a4ce7a17932c4aab8fc1b60bbe647059ded" +
                "54ac0df3af9c79b0d11404122b52d86bb7f808146cb0e1");

        Record record = new Record(ByteBuffer.wrap(clientHelloBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        Handshake handshake = new Handshake(record.fragment());
        assertEquals(Handshake.Type.CLIENT_HELLO, handshake.type());
        ClientHello clientHello = (ClientHello) handshake.body();

        record = new Record(ByteBuffer.wrap(serverHelloBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        handshake = new Handshake(record.fragment());
        assertEquals(Handshake.Type.SERVER_HELLO, handshake.type());
        ServerHello serverHello = (ServerHello) handshake.body();

        Random clientRandom = clientHello.random();
        Random serverRandom = serverHello.random();
        CipherSuite suite = serverHello.cipherSuite();
        ProtocolVersion protocolVersion = serverHello.version();

        KeyGenerator prf = new TestableKeyGenerator(new TLSPRFKeyGeneratorImpl(), new Jessie(), "TLS_PRF");
        byte[] KEY_EXPANSION = new byte[]{107, 101, 121, 32, 101, 120, 112,
                97, 110, 115, 105, 111, 110};
        byte[] seed = new byte[KEY_EXPANSION.length
                + clientRandom.length()
                + serverRandom.length()];
        System.arraycopy(KEY_EXPANSION, 0, seed, 0, KEY_EXPANSION.length);
        serverRandom.buffer().get(seed, KEY_EXPANSION.length,
                serverRandom.length());
        clientRandom.buffer().get(seed, (KEY_EXPANSION.length
                        + clientRandom.length()),
                clientRandom.length()
        );
        prf.init(new TLSKeyGeneratorParameterSpec("TLS_PRF", seed, masterSecret,
                 suite.keyLength(), 20, 0));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();
        System.out.printf("session keys:%nclient_write_key: %s%nclient_write_mac: %s%nserver_write_key: %s%nserver_write_mac: %s%nivs:c:%s s:%s%n",
                Util.toHexString(keys.getClientWriteKey()),
                Util.toHexString(keys.getClientWriteMACKey()),
                Util.toHexString(keys.getServerWriteKey()),
                Util.toHexString(keys.getServerWriteMACKey()),
                Util.toHexString(keys.getClientWriteIV()),
                Util.toHexString(keys.getServerWriteIV()));

        Cipher clientCipher = suite.cipher(protocolVersion.protocolVersion());
        Mac clientMac = suite.mac(protocolVersion.protocolVersion());
        clientMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), clientMac.getAlgorithm()));

        Cipher serverCipher = suite.cipher(protocolVersion.protocolVersion());
        Mac serverMac = suite.mac(protocolVersion.protocolVersion());
        serverMac.init(new SecretKeySpec(keys.getServerWriteMACKey(), serverMac.getAlgorithm()));

        InputSecurityParameters clientIn = new InputSecurityParameters(clientCipher, clientMac, null, protocolVersion,
                suite, new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().name()));
        InputSecurityParameters serverIn = new InputSecurityParameters(serverCipher, serverMac, null, protocolVersion,
                suite, new SecretKeySpec(keys.getServerWriteKey(), suite.cipherAlgorithm().name()));

        record = new Record(ByteBuffer.wrap(clientFinishedBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        ByteBuffer decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
        handshake = new Handshake(decrypted);
        assertEquals(Handshake.Type.FINISHED, handshake.type());

        record = new Record(ByteBuffer.wrap(clientAppBytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(clientAppBytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(serverFinishedBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(serverAppBytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(serverAppBytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(clientAlertBytes));
        assertEquals(ContentType.ALERT, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
        Alert alert = new Alert(decrypted);
        System.out.println(alert);
    }
}
