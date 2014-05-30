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

import org.junit.Test;
import org.metastatic.jessie.PrivateCredentials;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class TestPrivateCredentials
{
    public class CallbackHandlerImpl implements CallbackHandler
    {
        static final String password = "changeit";

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
        {
            for (Callback c : callbacks)
            {
                if (c instanceof PasswordCallback)
                    ((PasswordCallback) c).setPassword(password.toCharArray());
                else
                    throw new UnsupportedCallbackException(c);
            }
        }
    }

    static final String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: AES-128-CBC,2EA55E5A5B854F3B9D5D8CEB5A50C130\n" +
            "\n" +
            "A0YbEX6yTxj0BDvPjMrCfsUPbfiB6WdNe4h5i8ScxarvJk6IKOTsvt9rsk1pQuks\n" +
            "DaXaKY1NZbIQ1pJeYXOP2Wn9fiPPH4rot+l2pA1pV2o8cy0xhFCXNqd0KlrnEVzT\n" +
            "LvM5VlK+9JmGSl09wPQ/sSQOVefOEHq3xhxHcCLBRnLl67dpxPN8meYJIpGv4xFq\n" +
            "MbdWvqRnzW8cwQBTe76Zba4HurGoa9Wfes/z34ejZfmPD7/5Lw3XurIxC+Ay+bZM\n" +
            "Ozmr3dSjc2tpWKLR5mriDFkXs+YmTfbUqm1/nUVeb9YWhUHZvF3prirjaIND0Kpy\n" +
            "/65fEexuqp+v1Djjb5CnCXLuwZm7rGLAlLEGLAmCI2JW36sc0ov6a8aKQ+tm6+76\n" +
            "AonP6n9jfa2KNfG4FN+fWd4u+ki9GN9GYojbHUS2X0RUYJv8avvscanGjueJgolx\n" +
            "IcYHi1JIzZENJDf2DciOjUkR4LRuDQgQclSMrk3mAJ2jz3KjdQ5S9+B5lFVWwT48\n" +
            "1uTKi0inmDTKkWTkTIel3WYn4jznQ/fYkIy0NkPl4syim8C+zhoNFEBtOpPHq4VO\n" +
            "RI6jW+1TaBnwJyFtfhZnmHqMEAGFIdfJrEnkDcxEy4wUI0jAojkDy1l7T5tzzjYS\n" +
            "mN+2Npylsm1EaoQTX3DJo9G3VYonRqiXyCiY+Dv71csaWQihswhR+jzd5X32by3x\n" +
            "wDCUgJvtVRPNuy+K4snQ0jfCjAMiYNS84WaBX+Lh5IFGyCtt7ohQ/yhgYny3j05h\n" +
            "sLstPpdbeoxsqqzGRWK6gqKhQkiEkgz7wF6ghfjwkrMBTKi+Dpr3gjb7GjGmsfYv\n" +
            "hY6C5oeFZCUvtXTDTUZpdAXTXwAV6U8jHsaZ8JavE/1pHbipmpaB5TwdVzVCj1+T\n" +
            "NgEOmz5c6prwO//VmFu9/+pGCvV1B9ijqjHHyLZXsDW5rmdT+uU0aYJxjus7m28X\n" +
            "WnOWXASCidm2rjEqrPwaeuJYYLVndOXg1RNPvTsm+3bnGYFEwqztagTLRPjTTgWc\n" +
            "Ippkg45OZCxCVI5Lbt0rDHCToRsQxH9SFIGP8DyikNfzaSMFOONiSZvndFzdpw2i\n" +
            "VsXSlE6R5M72OxQ2sU7VMDw43m2cl+dRb3QOw/RS3lXkfxpV6I7l02a3A4TXo0Rs\n" +
            "KQwWUS0b2UMQyNiMDBChF+Wh2jsKrNDlnLrlanq3ZdfsifBo6h4PZRNbaSNxbk0C\n" +
            "wBviqVzzvyhr+kRnF6UZorgUyB5PtxdbIXLDx5u3VIOGxrAuqX0EiaNgygpjormN\n" +
            "0NnGkvK/se8RaBZPQdYxFTBQwOv8cfpxFedhrMLDtEHGmGh8J/i2hNoTSZdyk+IT\n" +
            "dnkh5e39d+Mu7hr8q2OWs8JIpczDixbGewnT067cA5H0FwT1kfLQm0L2b9KwBK/L\n" +
            "Agbd6cxgVJkO8qnU4v6tbo17za9jDoGCUsmdrtYwPuzHNQyJTBX+v7Fyb89qwjNZ\n" +
            "6yIqGO26QFJyHMnSxkc3p+3t1Z7jO2iXX5ClRcoffTo6KDMBCXGgA6IrMPx4MJsx\n" +
            "Hme60oZFguak0xDmhOYKJMOlONLRX81lIly4VMJEz5gMVqlJk+Hx3Tr28Qk0Y/vO\n" +
            "-----END RSA PRIVATE KEY-----\n";
    static final String cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzjCCArYCCQCMos5qqKRWejANBgkqhkiG9w0BAQUFADCBqDELMAkGA1UEBhMC\n" +
            "VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNVBAcTClNhbnRhIENydXoxFjAU\n" +
            "BgNVBAoTDU1vZGFsIERvbWFpbnMxEDAOBgNVBAsTB0hhY2tpbmcxFzAVBgNVBAMT\n" +
            "Dm1ldGFzdGF0aWMub3JnMSwwKgYJKoZIhvcNAQkBFh1jYXNleS5tYXJzaGFsbEBt\n" +
            "ZXRhc3RhdGljLm9yZzAeFw0xNDA1MzAyMDE4NDRaFw0xNTA1MzAyMDE4NDRaMIGo\n" +
            "MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTETMBEGA1UEBxMKU2Fu\n" +
            "dGEgQ3J1ejEWMBQGA1UEChMNTW9kYWwgRG9tYWluczEQMA4GA1UECxMHSGFja2lu\n" +
            "ZzEXMBUGA1UEAxMObWV0YXN0YXRpYy5vcmcxLDAqBgkqhkiG9w0BCQEWHWNhc2V5\n" +
            "Lm1hcnNoYWxsQG1ldGFzdGF0aWMub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAre3DWxzb4UlBh1jxD6wrNZzz936236jbBRY4qq0pxi4uitSVFZvU\n" +
            "Ncegk24dVyJHeud7BW0Z98xbhQy1piTJRf9lq4Zdo0L7mPcQOx6V1jrMR7UMPPTK\n" +
            "4av9YqNrRL4JpT844MRtNuDipl4p5hsQC8l3+/ejKe5sxovFq5evw7rfg2+KfbQ5\n" +
            "oM/vpyTlRLdNEOXbJTq8O+6WIvsBsNcnoPsce+c2670TYUdIp0dPkoZnROVSY2Pd\n" +
            "LbqZPUmSUwvEnQF1KqMHGkjywbnBWV+mmAh3YTBUEDD2DhC8ToOm+jAqBJ9fERSo\n" +
            "pCG6FxOLfk5aljjzvBUV2C9wMHc5xaIReQIDAQABMA0GCSqGSIb3DQEBBQUAA4IB\n" +
            "AQB96/Dbglqs35RKfs+hWRsjp02doe/06Mdn2psJiFFj1XsMqmsBL8HCftXedMML\n" +
            "v+t3j9dseBV5ftw65e3KNvlhHIz9cVPaZITM62xI0amic3mX0Mh1CtKdKToRtjc2\n" +
            "biX2lBN5QFieIF2ik6jgqCZI7BsB8+EnkoJ2s4BgKxWcXZjTkfZ6nqyNbZssaHPZ\n" +
            "v7qXIKlONsUWqclZu7B688IP8jTu64WeqAlHW4Sw8FQ4CMNqwLTg1opF9zIY3wtT\n" +
            "oLkZzGwQTsf2TsDoFetkVpshMY/v2xrS7/cbUtws/b0TaSuqPqLXIGQgoPg5IZIe\n" +
            "6F5+DETFQ7W4dnxyT6TZ6quC\n" +
            "-----END CERTIFICATE-----\n";

    @Test
    public void test1() throws Exception
    {
        PrivateCredentials creds = new PrivateCredentials();
        System.setProperty("org.metastatic.jessie.passwordCallbackHandler", "org.metastatic.jessie.test.TestPrivateCredentials$CallbackHandlerImpl");
        creds.add(new ByteArrayInputStream(cert.getBytes()), new ByteArrayInputStream(key.getBytes()));
    }
}
