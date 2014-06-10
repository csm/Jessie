package org.metastatic.jessie.test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;
import org.metastatic.jessie.SSLProtocolVersion;
import org.metastatic.jessie.provider.*;

import static org.junit.Assert.assertEquals;

/**
 */
public class TestSampleSessionAES_CBC_TLS1
{
    // openssl s_client -cipher DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA -connect www.google.com:443 -tls1
    // Then, type in "GET /x HTTP/1.0\n\n"

    /*
New, TLSv1/SSLv3, Cipher is AES128-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1
    Cipher    : AES128-SHA
    Session-ID: 0229912CAF971FAB1FE56881B0FB83074B6E0351686AF5CD6E3616B250405C85
    Session-ID-ctx:
    Master-Key: 3C36223900B0D3F54086C75E93592DACD3448C0241FA994FDADF8ABDB9C0C5872A44C4B06A4DCD5C1C29B2F3D2AFDD9E
    Key-Arg   : None
    TLS session ticket lifetime hint: 100800 (seconds)
    TLS session ticket:
    0000 - a8 04 03 32 2c 88 d3 2f-12 bd 2f b8 74 98 13 30   ...2,../../.t..0
    0010 - 11 e8 17 8b 79 b0 9b 51-6d 9f 52 51 72 3e fb 90   ....y..Qm.RQr>..
    0020 - 84 d6 5a 7b 0e 3b af ea-97 b2 b5 ea c2 18 e9 25   ..Z{.;.........%
    0030 - a7 5d 75 3e 2c 55 b6 6a-e1 5c ec 4a 77 4b 36 f8   .]u>,U.j.\.JwK6.
    0040 - ea 8a 95 37 e6 b3 b6 23-53 e8 29 d7 09 dd f4 73   ...7...#S.)....s
    0050 - 97 4b a8 e4 af 3e c8 61-1c 57 54 66 ae 90 11 18   .K...>.a.WTf....
    0060 - 7f 9c 00 0f 6b cf 40 32-b4 59 38 00 5a 99 e1 42   ....k.@2.Y8.Z..B
    0070 - cc 84 45 57 1b 38 72 45-12 67 a6 52 ca f5 04 c7   ..EW.8rE.g.R....
    0080 - 9b 47 00 c7 5f a5 3f 33-9b 16 97 95 80 b8 e6 68   .G.._.?3.......h
    0090 - 72 be 0b a2 83 05 f0 e6-cc 75 1a a0 4e 82 0a 62   r........u..N..b
    00a0 - 40 62 5f 32                                       @b_2

    Start Time: 1402287282
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
     */

    @Test
    public void test() throws Exception {
        Logger logger = Logger.getGlobal();
        logger.setLevel(Level.FINE);

        byte[] masterSecret = Util.toByteArray("3C36223900B0D3F54086C75E93592DACD3448C0241FA994FDADF8ABDB9C0C5872A44C4B06A4DCD5C1C29B2F3D2AFDD9E");
        byte[] clienthelloBytes = Util.toByteArray("160301003f0100003b0301539534b25cef802bc98a5738abe69bc8cfb68ccb616b91ae8ed4251bc7ba8bf600000e00390038003500330032002f00ff0100000400230000");
        byte[] serverhelloBytes = Util.toByteArray("1603010035020000310301539534b279d48d73d98b1de3b8d160027293c2e0e75326add3de83ad0cd4b8a900002f000009ff0100010000230000");
        byte[] certificateBytes = Util.toByteArray("1603010c130b000c0f000c0c00047a308204763082035ea003020102020808d320df44a8a623300d06092a864886f70d01010505003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3134303532323131323535385a170d3134303832303030303030305a3068310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633117301506035504030c0e7777772e676f6f676c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a02820101008d252c243cfa4c830fc9fdd885e5c02a19b98d7bf062875acb56c7c1c090d2df3ba7c4c235200868b9d71cb9077487839661c19ccf563c68dbe93f3fb7a98d0652f41c5462e1f09c9d40923c7819572fdbfc27fb8ad86053ff7ec191c81af780eaa4e2c6f67e45bec77a17cefe8e9b82c835d6d61bfa68daf8ba2c85c1aec8dc79534abe816ae33e692d0f5d44c94818b4046ef78096e94c1fcc8059482e9df1e5b612a67fb779274c13810a12ae36bb2fe854716b5ec81903afe599632233f22ce77d311497eed01cfb3a03d162c0221a21a384fc8f52ce284ce40446ada3f5c20ce0e5c756d66a7a111213a9e80ef94d869b4047eea5a4fa03810a763b90630203010001a38201413082013d301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e7777772e676f6f676c652e636f6d306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414000bfe82577d698b001a8a64797f538afd076295300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30170603551d200410300e300c060a2b06010401d67902050130300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d010105050003820101007724e0f0e144d45f7c49cabe79adb77910878c42372cb0a46f1ffa0998470897586b39a88d9e911b422b3ed8de584763cc314f36e623b7d0beba848b303cec5f16205e6f564c4d63c91b9597c7b7dcb453c35db277663ab7700348697f1596ee2749ac8d1212a736e6688356154ab83732edc4fbc2e76f3b7ea596bd8931fcdb586efe29774e64735e7753ddd133fa7d5792b4f717d3412f767261c783539b81f5fa3bc76e47a4b3fff29c48aaedfe01ca06a8d989a7149f5a56aa297a9ddd367ef9e747b604cee6df0a57ae4680243df969746a6b46a1d4f4bc62347913d197ab3e36793a020bb3e1b9113ec613b8454974477717e7fd9311eb55623473e27800040830820404308202eca0030201020203023a69300d06092a864886f70d01010505003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3133303430353135313535355a170d3135303430343135313535355a3049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f7269747920473230820122300d06092a864886f70d01010105000382010f003082010a02820101009c2a04775cd850913a06a382e0d85048bc893ff119701a88467ee08fc5f189ce21ee5afe610db7324489a0740b534f55a4ce826295eeeb595fc6e1058012c45e943fbc5b4838f453f724e6fb91e915c4cff4530df44afc9f54de7dbea06b6f87c0d0501f28300340da0873516c7fff3a3ca737068ebd4b1104eb7d24dee6f9fc3171fb94d560f32e4aaf42d2cbeac46a1ab2cc53dd154b8b1fc819611fcd9da83e632b8435696584c819c54622f85395bee3804a10c62aecba972011c739991004a0f0617a95258c4e5275e2b6ed08ca14fcce226ab34ecf46039797037ec0b1de7baf4533cfba3e71b7def42525c20d35899d9dfb0e1179891e37c5af8e72690203010001a381fb3081f8301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e301d0603551d0e041604144add06161bbcf668b576f581b6bb621aba5a812f30120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f6774676c6f62616c2e63726c303d06082b060105050701010431302f302d06082b060105050730018621687474703a2f2f6774676c6f62616c2d6f6373702e67656f74727573742e636f6d30170603551d200410300e300c060a2b06010401d679020501300d06092a864886f70d0101050500038201010036d706801127ad2a149b3877b323a07558bbb17e8342ba72da1ed88e360697e0f0953b37fd1b4258fe22c86bbd385ed13b256e12eb5e6776464090da14c8780ded9566da8e866f80a1ba56329586dcdc6aca048c5b7ff6bfcc6f850358c3685113cdfdc8f7793d9935f056a3bde059ed4f4409a39e387af646d11d129d4fbed040fc55fe065e3cda1c56bd96517b6f572adba2aa96dc8c74c295bef06e9513ff17f03cacb2108dcc73fbe88f02c6f0fb33b3953be3c2cb685873dba824623b06359d0da933bd7803902e4c785d503a81d4eea0c87038dcb2f967fa87405d61c0518f6b836bcd053acae1a70578fccada94d02c083d7e1679c8a05020245433710003813082037d308202e6a003020102020312bbe6300d06092a864886f70d0101050500304e310b30090603550406130255533110300e060355040a130745717569666178312d302b060355040b1324457175696661782053656375726520436572746966696361746520417574686f72697479301e170d3032303532313034303030305a170d3138303832313034303030305a3042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c20434130820122300d06092a864886f70d01010105000382010f003082010a0282010100dacc186330fdf417231a567e5bdf3c6c38e471b77891d4bca1d84cf8a843b603e94d21070888da582f663929bd05788b9d38e805b76a7e71a4e6c460a6b0ef80e489280f9e25d6ed83f3ada691c798c9421835149dad9846922e4fcaf18743c11695572d50ef892d807a57adf2ee5f6bd2008db914f8141535d9c046a37b72c891bfc9552bcdd0973e9c2664ccdfce831971ca4ee6d4d57ba919cd55dec8ecd25e3853e55c4f8c2dfe502336fc66e6cb8ea4391900b7950239910b0efe382ed11d059af64d3e6f0f071daf2c1e8f6039e2fa36531339d45e262bdb3da814bd32eb180328520471e5ab333de138bb073684629c79ea1630f45fc02be8716be4f90203010001a381f03081ed301f0603551d2304183016801448e668f92bd2b295d747d82320104f3398909fd4301d0603551d0e04160414c07a98688d89fbab05640c117daa7d65b8cacc4e300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f73656375726563612e63726c304e0603551d200447304530430604551d2000303b303906082b06010505070201162d68747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f7279300d06092a864886f70d01010505000381810076e1126e4e4b1612863006b28108cff008c7c7717e66eec2edd43b1ffff0f0c84ed64338b0b9307d18d05583a26acb36119ce84866a36d7fb813d447fe8b5a5c73fcaed91b321938ab973414aa96d2eba31c140849b6bbe591ef8336eb1d566fcadabc736390e47f7b3e22cb3d07ed5f38749ce303504ea1af98ee61f2843f12");
        byte[] clientkexBytes = Util.toByteArray("1603010106100001020100251710c600fcd4743022c345801b6d2ee8b6881c008e40831fd453eef11316419350cbcc49fb89b43005ccbeb8e5ff27183bd904c88de1686e692be8789a4e86b9b575fff7b8ed14e7b2b3440364a625d0b69e637d525d277ed99dfbb788c86aad94322aef50f9c8a49eddb84d4fd0abbd2fb3c8178cb55f3b0c21d765b9ba5c9d52f3567df05a5e6fd07dd0ce5b32c3e1fe09fb3ecc7f911a7a808b1e7338cf2b1f921885f190a4a7f8ba5a669885dedb70a14431dfd10616ce2e109445e02937e29adf4c85507db20e5dc8ad53dc7ba9f51f548ef273a2b8177d723e6ee163ca1235b384822408b862ce4c2d7613bd525abcaca029070d49b1df3ba14ae510");
        byte[] clientchangeBytes = Util.toByteArray("140301000101");
        byte[] clientFinishedBytes = Util.toByteArray("16030100305f661fd6ce4b31538cd93d36838d7a69f0b30b5b2ddce117b47833ba241eeddc0398e68b827741f7846e56a9ee2e9351");
        byte[] servernewticketBytes = Util.toByteArray("16030100ae040000aa000189c000a4a80403322c88d32f12bd2fb87498133011e8178b79b09b516d9f5251723efb9084d65a7b0e3bafea97b2b5eac218e925a75d753e2c55b66ae15cec4a774b36f8ea8a9537e6b3b62353e829d709ddf473974ba8e4af3ec8611c575466ae9011187f9c000f6bcf4032b45938005a99e142cc8445571b3872451267a652caf504c79b4700c75fa53f339b16979580b8e66872be0ba28305f0e6cc751aa04e820a6240625f32");
        byte[] serverchangeBytes = Util.toByteArray("140301000101");
        byte[] serverfinishedBytes = Util.toByteArray("16030100300d4de4d7404b6df86c01291f7070cbae3dbf76f08d7da161bbe7cbe907b2765190423aaf50ff6cd38e8096ffe5fba283");
        byte[] clientappbytes1 = Util.toByteArray("1703010020e25c7dd85c810df13f626cab1d7b131900e5b769de50cdfd3bbe951d59168209");
        byte[] clientappbytes2 = Util.toByteArray("17030100307303106a920d6a353e4ed410cb2d70f851370b0d1119a6f58be32d37e82eb1365439c27ab97c25133eb7c468e17b4e38");
        byte[] clientappbytes3 = Util.toByteArray("170301002005562b4ba55e354d1febe749b3c5721f8800de567953021d717e668cdfcb0f9c");
        byte[] clientappbytes4 = Util.toByteArray("1703010020170c713e09c954067055decfb197718b4ec30ac29fd618386ed55d7d391a5efa");
        byte[] serverappbytes1 = Util.toByteArray("17030105805ee746a0861d530c330c75ea7119a02767ccb90decdb5ba70158aa4a7ea9cc74a3e89529c5b2ddaa345a80df279b097fe2d081429061f239b5b660a94b8f34b3a1e39174cfe143c811075da3853afd3c13785e4013a1ea813af8f4a9c9d92fe3bd80f54c227faa5d21f2195edaa80beca3adb0155c6cc68d61a81711a8938aee7f2c009514c1c6e43898ba1b407100e58911ad58f210b041274e63dec030ba2f79fac1889f680d582becb95db831cb95526e2ce0e5e7ca045f99baa78993622180e4d65b014c14b392dcc592a26a1154c84668a47faccdb9ab2528f47f527c6d13bc6f3efb30cc4056b001cd2293eac4f749d366e0e23e2862142ebcd5e0e12371f5a02fd2ae95cbfe0c2c22c956ede91945ac66157800882da8e6b351c7b077164217041f747cf24aa5b3531361d3a4595d7f9bab625fe74d12571d117d66a8cf296ccd3c0b55d1ed0983cc6ff3fe9430a9ede8a3ac6be0d4db0ba3219ece458b6cbe507df581e270c28d02ee9f3934c579086c9fbe8ae9af5829a791bdf2068aed350f8d033639bbcd8982df82c8aac64f12da3f300f91585be518a59505fd42fe2c9d00e3a5df7cd41e507cd927d4efabbaeda3963fa8062f1b66f703ddada4d8cd5160d055584ddd67216057a617aede95a72b9c57b399cb071810ef37c7f06950108815dd1f26247c44eb4549dbfb76bb815da6c77e8e9640f0815b26fe733c2bb5818ec0fce538e5bd2e4cf0e12847bd81aa39f41f5dae7ecd9ba7a9ca0e4bc2debf4d827dfab6639e3ff60b7a1aec610d975277154591f7dba710effc25e7abf08ce47020acd9e3c55e63a63ba1e9644ea343f075968792a6ce029af392d5a115c3b00ffb3009c5c812c69ca83a6cf9fd0eff0ab983af5b02666bc8542d0cac3de250f8a2bada589b31d4d4be2dfdba59b08d166bee94f29548f16d2ad0a58782897897526e42f3d0f5caa893201ec63ee66da5d1478cbfe8750fdc14a25fc41e689b78c953662139bc3c64c9a0449c27d338be6f5a193319b35233f50f17040682005ea9bf507801cb1b3ffa8acd715f7fc31433f7a8647117d34f5bcf13974d09d01ef4a26afa6e28c8feb7dd60359218bafabba066582f159f50c6fb07db2d98ae08703e9063ffc4131152eb222f4649b390e0116ce4ef26e50d8b67a167e51b9bdacd234152c3caa230f274a8f0ad507cb741fe59d0b753677abbafd3072504318af14aef0a927054cadc9058df303a2f59aaeeadf60f2fd4cc978533f2b006d998e63c28fe28c465d05c3dbd8dfa014e503ccdee5154cc080e2bf158ed396cedbd5c3e5003060a1c507e5897afe3d8d94ba29987811296c28bc47d8928038ee33b7fca49a4d6da2562c702c0e458fd20451a8bfe48f17625d94e1f1640d6ffe9f11ef71edfeef2b6010493eb965256eccb48e7def255f5882dbe6fa61caec2f00f9abca6ad29da1b7554a180fec0190a00184c280420d159e13833d86d648dbef8b6909e861d90eda8ce2a907ea321b8eb69996a1788750ccf7da05ffc9d99619781df8ce03bd43b6c8e65d0a169e0d52ad60abeb31802d3a2cbb213fe0fd35c5f930de61d63d3e5a77f8514c74c6fa2f319f5ed1e6d6b728a749f647e66e811a1895fa058f3fde3373652b280f8e2e76c63a8a01b7bdd58255fcc514e103eed91c3b48ba581f33a9dc8a40c8dd40cdf3c9f38d7e1021e1b1f5a8b70e76b7d2d7909d97a6bdf4e56c36270f3eddea6e0c14a78c2aa06dd0718e642103fd72f8e6e254ca92c8beca3f67923f54d6a865dcad2378275bcfd918a806ee4d52aaea67e573d33d9ad1d18aec4029eadffa1f89daefdfaaa5777439250855d8f347c8e2e63c0274abd2786d9d2dfc6083bc41c7674823916363c66bcb4b70a228725698ba1cab72e64b2d7d537093aa629b9f28fa7d57e21050ebda060135e98a310bf94c51912033369992001bb17230ad9ed0fa6df5332017c5bc65b");
        byte[] serverappbytes2 = Util.toByteArray("17030100d07d21dddc90134a565e9baccfaa71db83d78012e44b722c7c5555c781eaea5da28ee7127d8653bf20c6299c23746ed0a4a72ce4c2c5f529229b52240ba7e520fbf7937e33be1be0db5553d215c0ff1af25a487744eb18eab4e894936af6b0c4cb3b5775022bc733320f94f0a79a6ed793e6cab8623cc48cd0934a93ec82484b665dd6fa70010c713d4a5f561f56b2b616add2bbf464a77ade8456852bc18a2fd379b881565a7e622fd77f8dcdebf3fcbf681a3832d892fa1a390cd94a09d082d59d835a7173af346ae112e33c9d746f1b");
        byte[] clientalertBytes = Util.toByteArray("150301002074b64b2b2d60b7b3e06fc8458a1ffba7e776c592240b6c0d8deb7360c724eea1");

        Record record = new Record(ByteBuffer.wrap(clienthelloBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        Handshake handshake = new Handshake(record.fragment());
        assertEquals(Handshake.Type.CLIENT_HELLO, handshake.type());
        ClientHello clientHello = (ClientHello) handshake.body();

        record = new Record(ByteBuffer.wrap(serverhelloBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        handshake = new Handshake(record.fragment());
        assertEquals(Handshake.Type.SERVER_HELLO, handshake.type());
        ServerHello serverHello = (ServerHello) handshake.body();

        CipherSuite suite = serverHello.cipherSuite();
        Jessie jessie = new Jessie();
        KeyGenerator prf = new TestableKeyGenerator(new TLSPRFKeyGeneratorImpl(), jessie, "TLS_PRF");
        byte[] KEY_EXPANSION = new byte[]{107, 101, 121, 32, 101, 120, 112,
                97, 110, 115, 105, 111, 110};
        final Random clientRandom = clientHello.random();
        final Random serverRandom = serverHello.random();
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
                 suite.keyLength(), 20, 16));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();
        System.out.printf("expanded keys:%nclient_write_mac: %s%nclient_write_key: %s%n client_write_iv: %s%n" +
                          "server_write_mac: %s%nserver_write_key: %s%n server_write_iv: %s%n",
                          Util.toHexString(keys.getClientWriteMACKey(), ':'),
                          Util.toHexString(keys.getClientWriteKey(), ':'),
                          Util.toHexString(keys.getClientWriteIV(), ':'),
                          Util.toHexString(keys.getServerWriteMACKey(), ':'),
                          Util.toHexString(keys.getServerWriteKey(), ':'),
                          Util.toHexString(keys.getServerWriteIV(), ':'));

        SSLProtocolVersion protocolVersion = serverHello.version().protocolVersion();
        Cipher clientCipher = suite.cipher(protocolVersion);
        clientCipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(keys.getClientWriteKey(), suite.cipherAlgorithm().toString()),
                new IvParameterSpec(keys.getClientWriteIV()));
        Mac clientMac = suite.mac(protocolVersion);
        clientMac.init(new SecretKeySpec(keys.getClientWriteMACKey(), clientMac.getAlgorithm()));
        System.out.printf("client cipher: %s client mac: %s%n", clientCipher.getAlgorithm(), clientMac.getAlgorithm());

        Cipher serverCipher = suite.cipher(protocolVersion);
        serverCipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(keys.getServerWriteKey(), suite.cipherAlgorithm().toString()),
                new IvParameterSpec(keys.getServerWriteIV()));
        Mac serverMac = suite.mac(protocolVersion);
        serverMac.init(new SecretKeySpec(keys.getServerWriteMACKey(), serverMac.getAlgorithm()));
        System.out.printf("server cipher: %s server mac: %s", serverCipher.getAlgorithm(), serverMac.getAlgorithm());

        InputSecurityParameters serverIn = new InputSecurityParameters(serverCipher, serverMac, null, serverHello.version(), suite);
        InputSecurityParameters clientIn = new InputSecurityParameters(clientCipher, clientMac, null, serverHello.version(), suite);

        record = new Record(ByteBuffer.wrap(certificateBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        handshake = new Handshake(record.fragment(), serverHello.cipherSuite(), serverHello.version());
        assertEquals(Handshake.Type.CERTIFICATE, handshake.type());
        Certificate certificate = (Certificate) handshake.body();

        record = new Record(ByteBuffer.wrap(clientkexBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        handshake = new Handshake(record.fragment(), serverHello.cipherSuite(), serverHello.version());
        assertEquals(Handshake.Type.CLIENT_KEY_EXCHANGE, handshake.type());
        ClientKeyExchange clientKeyExchange = (ClientKeyExchange) handshake.body();

        record = new Record(ByteBuffer.wrap(clientchangeBytes));
        assertEquals(ContentType.CHANGE_CIPHER_SPEC, record.contentType());

        record = new Record(ByteBuffer.wrap(clientFinishedBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        ByteBuffer decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        handshake = new Handshake(decrypted);
        assertEquals(Handshake.Type.FINISHED, handshake.type());
        System.out.printf("client finished (decrypted): %s%n", handshake);

        record = new Record(ByteBuffer.wrap(servernewticketBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        // Can't parse the handshake body until we support session tickets

        record = new Record(ByteBuffer.wrap(serverchangeBytes));
        assertEquals(ContentType.CHANGE_CIPHER_SPEC, record.contentType());

        record = new Record(ByteBuffer.wrap(serverfinishedBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        handshake = new Handshake(decrypted);
        assertEquals(Handshake.Type.FINISHED, handshake.type());
        System.out.printf("server finished (decrypted): %s%n", handshake);

        record = new Record(ByteBuffer.wrap(clientappbytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        int decryptedLen = clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("client app data decrypted %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(clientappbytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("client app data decrypted %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(clientappbytes3));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("client app data decrypted %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(clientappbytes4));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("client app data decrypted %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(serverappbytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = serverIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("server app data decrypted: %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(serverappbytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = serverIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        System.out.printf("server app data decrypted: %d:%n%s%n", decryptedLen, Util.hexDump((ByteBuffer) decrypted.duplicate().position(0).limit(decryptedLen)));

        record = new Record(ByteBuffer.wrap(clientalertBytes));
        assertEquals(ContentType.ALERT, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        decryptedLen = clientIn.decrypt(record, new ByteBuffer[] { decrypted }, 0, 1);
        Alert alert = new Alert(decrypted);
        System.out.printf("client alert:%n%s%n", alert);
    }
}
