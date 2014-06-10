/* 
   Copyright (C) 2014  Casey Marshall

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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

import org.junit.Test;
import org.metastatic.jessie.SSLProtocolVersion;
import org.metastatic.jessie.provider.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestSampleSessionAES_GCM_TLS1_2
{
    // C="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
    // openssl s_client -tls1_2 -cipher $C -connect www.google.com:443

    /*
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: 25650BF3B11101340ECF5026492E3BBE68B45B8242F628F6DE72593CBB88BE59
    Session-ID-ctx:
    Master-Key: 878CEB0F81A8672C31AD8ADBEA4EB373880F3B53C2D9108F141767BEA5AC0458274742A5BF4D5ED1D3CD625B5300A891
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 100800 (seconds)
    TLS session ticket:
    0000 - 19 51 65 2f 81 07 c6 cd-f4 43 3b 97 eb 92 70 ce   .Qe/.....C;...p.
    0010 - 61 61 71 3a 72 93 3b 24-c8 7f 7a 57 fa f2 2a 07   aaq:r.;$..zW..*.
    0020 - 1a 6f c7 a3 dd 23 7e b3-1e 48 f0 cb bf 62 86 48   .o...#~..H...b.H
    0030 - 97 7d ca 09 28 f4 f1 2a-b1 35 ed d1 67 b6 34 85   .}..(..*.5..g.4.
    0040 - 4c b5 f5 53 cc 06 4b 98-ba a4 0f 65 47 d2 1c 6a   L..S..K....eG..j
    0050 - ea c9 c0 c9 cf 37 f0 8d-fe 2c 17 43 70 ab ef d6   .....7...,.Cp...
    0060 - ca 63 6b c5 39 d7 71 1f-01 70 9b 88 3b c1 da 37   .ck.9.q..p..;..7
    0070 - 7a 33 73 bc 8c ff 4d d7-ad c6 fd 76 40 2e 8b 98   z3s...M....v@...
    0080 - 33 28 2c c2 8f a3 1a f1-08 19 da f7 96 74 fc cf   3(,..........t..
    0090 - c4 93 30 89 d4 43 05 1d-2c fa df 74 9f 3e 8e 1a   ..0..C..,..t.>..
    00a0 - 56 6d 23 c8                                       Vm#.

    Start Time: 1402344954
    Timeout   : 7200 (sec)
    Verify return code: 20 (unable to get local issuer certificate)
     */

    @Test
    public void test() throws Exception
    {
        byte[] masterSecret = Util.toByteArray("878CEB0F81A8672C31AD8ADBEA4EB373880F3B53C2D9108F141767BEA5AC0458274742A5BF4D5ED1D3CD625B5300A891");
        byte[] clientHelloBytes = Util.toByteArray("16030100b9010000b50303209a8792507051097ae31d425c37a1ac38c2956a79a3b449c48c4b9b97c5042500001ec030c02c00a3009fc032c02e009dc02fc02b00a2009ec031c02d009c00ff020100006d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101");
        byte[] serverHelloBytes = Util.toByteArray("160303003d020000390303539615f66a8e1061f7939e798ed3310b92bef11cea389ceef9030b2392ed86d400c02f000011ff01000100000b00040300010200230000");
        byte[] serverCertificateBytes = Util.toByteArray("1603030c130b000c0f000c0c00047a308204763082035ea003020102020808d320df44a8a623300d06092a864886f70d01010505003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3134303532323131323535385a170d3134303832303030303030305a3068310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633117301506035504030c0e7777772e676f6f676c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a02820101008d252c243cfa4c830fc9fdd885e5c02a19b98d7bf062875acb56c7c1c090d2df3ba7c4c235200868b9d71cb9077487839661c19ccf563c68dbe93f3fb7a98d0652f41c5462e1f09c9d40923c7819572fdbfc27fb8ad86053ff7ec191c81af780eaa4e2c6f67e45bec77a17cefe8e9b82c835d6d61bfa68daf8ba2c85c1aec8dc79534abe816ae33e692d0f5d44c94818b4046ef78096e94c1fcc8059482e9df1e5b612a67fb779274c13810a12ae36bb2fe854716b5ec81903afe599632233f22ce77d311497eed01cfb3a03d162c0221a21a384fc8f52ce284ce40446ada3f5c20ce0e5c756d66a7a111213a9e80ef94d869b4047eea5a4fa03810a763b90630203010001a38201413082013d301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e7777772e676f6f676c652e636f6d306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414000bfe82577d698b001a8a64797f538afd076295300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30170603551d200410300e300c060a2b06010401d67902050130300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d010105050003820101007724e0f0e144d45f7c49cabe79adb77910878c42372cb0a46f1ffa0998470897586b39a88d9e911b422b3ed8de584763cc314f36e623b7d0beba848b303cec5f16205e6f564c4d63c91b9597c7b7dcb453c35db277663ab7700348697f1596ee2749ac8d1212a736e6688356154ab83732edc4fbc2e76f3b7ea596bd8931fcdb586efe29774e64735e7753ddd133fa7d5792b4f717d3412f767261c783539b81f5fa3bc76e47a4b3fff29c48aaedfe01ca06a8d989a7149f5a56aa297a9ddd367ef9e747b604cee6df0a57ae4680243df969746a6b46a1d4f4bc62347913d197ab3e36793a020bb3e1b9113ec613b8454974477717e7fd9311eb55623473e27800040830820404308202eca0030201020203023a69300d06092a864886f70d01010505003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3133303430353135313535355a170d3135303430343135313535355a3049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f7269747920473230820122300d06092a864886f70d01010105000382010f003082010a02820101009c2a04775cd850913a06a382e0d85048bc893ff119701a88467ee08fc5f189ce21ee5afe610db7324489a0740b534f55a4ce826295eeeb595fc6e1058012c45e943fbc5b4838f453f724e6fb91e915c4cff4530df44afc9f54de7dbea06b6f87c0d0501f28300340da0873516c7fff3a3ca737068ebd4b1104eb7d24dee6f9fc3171fb94d560f32e4aaf42d2cbeac46a1ab2cc53dd154b8b1fc819611fcd9da83e632b8435696584c819c54622f85395bee3804a10c62aecba972011c739991004a0f0617a95258c4e5275e2b6ed08ca14fcce226ab34ecf46039797037ec0b1de7baf4533cfba3e71b7def42525c20d35899d9dfb0e1179891e37c5af8e72690203010001a381fb3081f8301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e301d0603551d0e041604144add06161bbcf668b576f581b6bb621aba5a812f30120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f6774676c6f62616c2e63726c303d06082b060105050701010431302f302d06082b060105050730018621687474703a2f2f6774676c6f62616c2d6f6373702e67656f74727573742e636f6d30170603551d200410300e300c060a2b06010401d679020501300d06092a864886f70d0101050500038201010036d706801127ad2a149b3877b323a07558bbb17e8342ba72da1ed88e360697e0f0953b37fd1b4258fe22c86bbd385ed13b256e12eb5e6776464090da14c8780ded9566da8e866f80a1ba56329586dcdc6aca048c5b7ff6bfcc6f850358c3685113cdfdc8f7793d9935f056a3bde059ed4f4409a39e387af646d11d129d4fbed040fc55fe065e3cda1c56bd96517b6f572adba2aa96dc8c74c295bef06e9513ff17f03cacb2108dcc73fbe88f02c6f0fb33b3953be3c2cb685873dba824623b06359d0da933bd7803902e4c785d503a81d4eea0c87038dcb2f967fa87405d61c0518f6b836bcd053acae1a70578fccada94d02c083d7e1679c8a05020245433710003813082037d308202e6a003020102020312bbe6300d06092a864886f70d0101050500304e310b30090603550406130255533110300e060355040a130745717569666178312d302b060355040b1324457175696661782053656375726520436572746966696361746520417574686f72697479301e170d3032303532313034303030305a170d3138303832313034303030305a3042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c20434130820122300d06092a864886f70d01010105000382010f003082010a0282010100dacc186330fdf417231a567e5bdf3c6c38e471b77891d4bca1d84cf8a843b603e94d21070888da582f663929bd05788b9d38e805b76a7e71a4e6c460a6b0ef80e489280f9e25d6ed83f3ada691c798c9421835149dad9846922e4fcaf18743c11695572d50ef892d807a57adf2ee5f6bd2008db914f8141535d9c046a37b72c891bfc9552bcdd0973e9c2664ccdfce831971ca4ee6d4d57ba919cd55dec8ecd25e3853e55c4f8c2dfe502336fc66e6cb8ea4391900b7950239910b0efe382ed11d059af64d3e6f0f071daf2c1e8f6039e2fa36531339d45e262bdb3da814bd32eb180328520471e5ab333de138bb073684629c79ea1630f45fc02be8716be4f90203010001a381f03081ed301f0603551d2304183016801448e668f92bd2b295d747d82320104f3398909fd4301d0603551d0e04160414c07a98688d89fbab05640c117daa7d65b8cacc4e300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f73656375726563612e63726c304e0603551d200447304530430604551d2000303b303906082b06010505070201162d68747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f7279300d06092a864886f70d01010505000381810076e1126e4e4b1612863006b28108cff008c7c7717e66eec2edd43b1ffff0f0c84ed64338b0b9307d18d05583a26acb36119ce84866a36d7fb813d447fe8b5a5c73fcaed91b321938ab973414aa96d2eba31c140849b6bbe591ef8336eb1d566fcadabc736390e47f7b3e22cb3d07ed5f38749ce303504ea1af98ee61f2843f12");
        byte[] serverKeyExchangeBytes = Util.toByteArray("160303014d0c00014903001741040c2d360f5a5eaca43d2c29f2fc7a3d246b1534325cfb566992cf8a5f8f4e254d88feebe511a50acaf1429519ef1eabe8732b90410b49a5ccaaf8061cd3924977060101000ddfd395f3432bd4010f4c58fb5f99a5b5e39826e49bc1953ba8bf3f8e4429e6d1125194e5cf2c330f29896333047d4fd1c145be98bd4951a452ea98a194aca6046888a8ab6ebd403c0efd9c1f2e5c4df92485fe88f92f0f14d0e022bcddb140b2d660f352fbfbe8409ffb94c55be68bf056e9da565865d53770b2c28f870c084c12a5694c540fefe5d4129c60deed84a85b1903db4f3fd44eec3f9e62d03f228f29b7ee00eb270ff183a092f3b607a5ca2ec19065054a59dafed0ccbae468e25017ea95adfc46d71defe046bd6c805d1f7b3272e3e7e79d937703c8df74013dfa46500376763aac28aae0f68577c9fbaad927ca75465b4a086c976047b8d49e");
        byte[] serverHelloDone = Util.toByteArray("16030300040e000000");
        byte[] clientKeyExchangeBytes = Util.toByteArray("16030300461000004241049de30fa42c278856f7ae4089bb3cbf282d4be21bc5450cef1f84d511097979ad5cab92db735f5d01f20bc7f78156603f92228689d5505d381c83bd1ddf245a9e");
        byte[] clientChangeCipherSpecBytes = Util.toByteArray("140303000101");
        byte[] clientFinishedBytes = Util.toByteArray("16030300288918c94f874a2d50f63ce0ac0dabe4c1f86b15cb9b58a039d8893b52cb5f35c0cfd9e26fb974233d");
        byte[] serverNewSessionTicketBytes = Util.toByteArray("16030300ae040000aa000189c000a41951652f8107c6cdf4433b97eb9270ce6161713a72933b24c87f7a57faf22a071a6fc7a3dd237eb31e48f0cbbf628648977dca0928f4f12ab135edd167b634854cb5f553cc064b98baa40f6547d21c6aeac9c0c9cf37f08dfe2c174370abefd6ca636bc539d7711f01709b883bc1da377a3373bc8cff4dd7adc6fd76402e8b9833282cc28fa31af10819daf79674fccfc4933089d443051d2cfadf749f3e8e1a566d23c8");
        byte[] serverChangeCipherSpecBytes = Util.toByteArray("140303000101");
        // For some reason we got two zero-length handshake messages before the encrypted finished message.
        // Or, maybe this is has something to do with GCM mode. Still investigating...
        byte[] serverFinishedEtcBytes = Util.toByteArray("16030300280000000000000000a48d549d17099badc5b8ffd46d8e2beef473eb15f77de7524afb3950427851ea");
        byte[] clientAppDataBytes1 = Util.toByteArray("17030300288918c94f874a2d518c50d524a23434ef1bd17680697d445f2362571ca50accf93faaa37b7a1a4095");
        byte[] clientAppDataBytes2 = Util.toByteArray("17030300198918c94f874a2d52dc7d876d0d74148ba785e373ba10a20625");
        byte[] serverAppDataBytes1 = Util.toByteArray("1703030573000000000000000178eb4edad2977a5dc4812f9fd7f04802b5fbe33710f64717077127e4829b7b5db3a5851752c348c57a7e77e0f71d80c7d3c79d809dc9000f4ac17d229fc22a8446ed4d74369ccbc5837fca6ae303a4c2bbb15fdd8c5bd40090a72a293cdc47ef8de873f7bcb72eac22e2504206977d96af093236ab78cf4aa9096831d1907c42155fb8efb6355f19160e27c503adf01c86e558204254bd43daced9f4d0f7d4c5535073fb7bf2f06f121c3f76fa53fcc75163d9a4760c7987a1a0e8e27bd3d46760ca7df9fcef26c0a7e9f056b87990d7fddd320041aa6692207d1c2e0cd3fda3f506146d4c40dec0fbf3748954ca29d321ecb535adbee5da87af7cf6d6c5dc3f8120e22dc5e4346e7182028caa1caff0299e7a0637e9c1b5bda2b450893f85a9b33af440493953948f61985832c6c851a6a3cf5f63312925e88fe24b37faf5c9b7a2feb69e088a756660763620f832a53622a9853232d789d9b86c27e13dd1ad8ff19bde97b6ef65053aff496599faeffa330967b2cfd4f2463dadcfba5d403d6fb4a8c76404afb2b80a5a3ebd662edb28279d22539fc461499ebfa60ac3f5f96a7a45b3e26a189b35a384c906f457d1aa958818d0d5a78bccfc80f714072486fd80ffce680c203710a31755aaa099b3ef34b92394d9b85e4e644cce69a8b2a7555255ba0dad7ff58396bcf637be4a321948b622c3485672452b77af8c21e10eef06f95e4e14f51a0629a18f942476e9220ebd2a7b74e5a31bb759f3da06457c47f7905b0ee321f289ea63fb81aa898826ec791ca54e478e64a6a80d2ede91251addcc78c3947cc0cee7ab6788a7716c2052df26ced0e441e63e01d5d0cb18d56ca9ff629e02485ea66a1034705b36b739fa9ef62178d5c79508c55721470a02e2662fa7fe25d1bc276cd6083271b9c3f882cb3ea75dca6e22685e79871439d4174693518dc56aede5126c18659c2c31947df405f5282ac5a30818cb5a483bc8e27be03c968418b45d2227c7db6bf36c549dc168543048b0ddf3b9e1705ee5bf3be38e9e051cf083d22041128c06de9d45705f6d80dea6c1a9c529946b32f2953364723ec6a686624aefccabcbb4841d62f6abc913db2907a2b1bf02760899122aa52be5eddb50cf57eccf8b6b5291637287b167f540214135a25162c0b7bc0b0ac30078c4910d95dba1f010b44fd836ba8b81eec05b73b1a842d83c1b86244b7973a511d9d8c07af916c3c4457d43a7db2517dae3224f7cdf22d5cd70c40248bdf1ad4a3e195b0219976ed95b94c576a2164af48fcb07417e90ed35005259779eb864b90e96268139bc1b4c0b7091810194eb47b992940a4924ef7890f6f039d06eb16dbae72dcd97a652fbab367d3eeb6e8f0925b623802d3999b35f15ecf3e17c7d3d1d645b8757a8dfd3dbe3f1edee9b51356a0e23302561a383206ca0b2b2cba0776c791e6b955e995ef383932b6609ee351e6f376f1ea8d498fe59313192357aa3274c064b429c5b68c8e86078c1b8fec75f326318e8933d974d38d396e4974c70cd6e747e565698e0542936892e2f39a58ce98b5eb8e0f487fa2351aedc7983876f6ba49e6b0008bf2bc11159d9361940100625e03e89715c2fc90be7fb42272182ea0c1f8b1f69efbc5c79db59255bd2bb1fc59c40552e44a3c267dd396b78fc0e06f928b84844ca2f82b3497921a38a4bdb4b5a9baf7ef4fb3494703ac506795f201a193c8cde5c73b79643f0510a8b5951b230d57d46c5d5fe0d6e8c712bb05aea67b0b32f1f9c6377bb2de68138712c3b5ec25ae65dc71f0b5e260c2ec99b2ba7b93a7792df4d19bd5d79cd9d6e149826f112f557fd18023ee6c213ceda951449b3ba6c938206fd65c435e7c6a0784e7434dfaac4f9466a9dbf1420cc241e97d28f15ccb37024ecd91c46c1edb235e31f71eb78626d0b05cbe9f6abdbb5672773a496ad487b");
        byte[] serverAppDataBytes2 = Util.toByteArray("17030300dd00000000000000027b812245ae519990fe80a5b50b95ba28953fbed4ea8a1102db17caba1356e010d2e54b473d31d6503ed302decbc42bfb0aa556982f56f5b181a5983705aba64b8e3cdc26f43d0e0b2004720dd520b5f97d225fa0352be51d76e154cdf416f2576218134185696d3cc72dbcbfed3fdbbbbff299b47182e15a51ebe90a24b25d4715e6eb1e340a3d7a5c5cf7cb8eee7a4dd061dcba951d4ff3e16b56ac78f7f06a088993b61de8635d4171f9ae5a970bf7788649bc1533f8a425ce5515d2de23c003fc66656b5995ec77ee0feb9ab17805db1e717815");
        byte[] clientAlertBytes = Util.toByteArray("150303001a8918c94f874a2d53fbea43559247c09bd34be87fa9558bc6d0b2");

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

        record = new Record(ByteBuffer.wrap(serverCertificateBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        handshake = new Handshake(record.fragment());
        assertEquals(Handshake.Type.CERTIFICATE, handshake.type());

        CipherSuite suite = serverHello.cipherSuite();
        assertTrue(suite.getClass().equals(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.class));

        Jessie jessie = new Jessie();
        KeyGenerator prf = new TestableKeyGenerator(new TLSKeyGenerators.TLSKeyGeneratorSHA256(), jessie, "P_SHA256");
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
        prf.init(new TLSKeyGeneratorParameterSpec("P_SHA256", seed, masterSecret,
                suite.keyLength(), 0, 4));
        TLSSessionKeys keys = (TLSSessionKeys) prf.generateKey();
        if (TestDebug.DEBUG)
            System.out.printf("session keys:%nclient_write_key: %s%n client_write_iv: %s%nserver_write_key: %s%n server_write_iv: %s%n",
                Util.toHexString(keys.getClientWriteKey(), ':'),
                Util.toHexString(keys.getClientWriteIV(), ':'),
                Util.toHexString(keys.getServerWriteKey(), ':'),
                Util.toHexString(keys.getServerWriteIV(), ':'));

        SSLProtocolVersion protocolVersion = serverHello.version().protocolVersion();
        Cipher clientCipher = suite.cipher(protocolVersion);
        Cipher serverCipher = suite.cipher(protocolVersion);

        InputSecurityParameters clientIn = new InputSecurityParameters(clientCipher, null, serverHello.version(), suite,
                new SecretKeySpec(keys.getClientWriteKey(), "AES"), keys.getClientWriteIV(), 128);
        InputSecurityParameters serverIn = new InputSecurityParameters(serverCipher, null, serverHello.version(), suite,
                new SecretKeySpec(keys.getServerWriteKey(), "AES"), keys.getServerWriteIV(), 128);

        record = new Record(ByteBuffer.wrap(clientFinishedBytes));
        if (TestDebug.DEBUG)
            System.out.printf("client finished (encrypted) %d:%n%s%n", clientFinishedBytes.length, record);
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        ByteBuffer decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
        handshake = new Handshake(decrypted);
        assertEquals(Handshake.Type.FINISHED, handshake.type());

        record = new Record(ByteBuffer.wrap(serverFinishedEtcBytes));
        assertEquals(ContentType.HANDSHAKE, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
        handshake = new Handshake(decrypted);
        assertEquals(Handshake.Type.FINISHED, handshake.type());

        record = new Record(ByteBuffer.wrap(clientAppDataBytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(clientAppDataBytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(serverAppDataBytes1));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(serverAppDataBytes2));
        assertEquals(ContentType.APPLICATION_DATA, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        serverIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);

        record = new Record(ByteBuffer.wrap(clientAlertBytes));
        assertEquals(ContentType.ALERT, record.contentType());
        decrypted = ByteBuffer.allocate(record.length());
        clientIn.decrypt(record, new ByteBuffer[]{decrypted}, 0, 1);
        Alert alert = new Alert(decrypted);
    }
}
