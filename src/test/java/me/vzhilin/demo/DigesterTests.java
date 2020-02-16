package me.vzhilin.demo;

import me.vzhilin.auth.digester.Digester;
import me.vzhilin.auth.digester.Ha1;
import me.vzhilin.auth.parser.ChallengeResponse;
import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.QopOptions;
import org.junit.Test;

import java.text.ParseException;

import static junit.framework.TestCase.*;

public class DigesterTests {
    @Test
    public void testChallengeResponseParser() throws ParseException {
        String realm = "testrealm@host.com";
        String nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
        String opaque = "5ccc069c403ebaf9f0171e9517f40e41";
        boolean stale = true;

        ChallengeResponse response =
            ChallengeResponse.of("Digest realm=\"" + realm + "\","
                + "qop=\"auth,auth-int\","
                + "nonce=\"" + nonce + "\","
                + "stale=" + stale + ","
                + "algorithm=MD5-sess,"
                + "opaque=\"" + opaque + "\"");
        assertTrue(response.hasQop(QopOptions.AUTH));
        assertTrue(response.hasQop(QopOptions.AUTH_INT));
        assertEquals(stale, response.isStale());
        assertSame(response.getAlgorithm(), DigestAlgorithm.MD5_SESS);
        assertTrue(response.getNonce().contains("dcd98b7102dd2f0e8b11d0f600bfb0c093"));
        assertTrue(response.getOpaque().contains("5ccc069c403ebaf9f0171e9517f40e41"));
        assertTrue(response.getRealm().contains("testrealm@host.com"));
    }

    @Test
    public void testDigesterMD5() {
        String response = "6629fae49393a05397450978507c4ef1";
        Digester d = new Digester();
        d.setAlgorithm(DigestAlgorithm.MD5);
        d.updateNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093");
        d.setQop(QopOptions.AUTH);
        d.setNonceCount(1);
        d.setCnonce("0a4f113b");
        final Ha1 ha1 = Ha1.hash(DigestAlgorithm.MD5, "Mufasa", "testrealm@host.com", "Circle Of Life");
        assertEquals(response, d.response(ha1,"/dir/index.html", "GET"));
    }

//    @Test
//    public void testDigesterSHA256() {
//        String response = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1";
//        Digester d = new Digester();
//        d.setRealm("http-auth@example.org");
//        d.setAlgorithm(DigestAlgorithm.SHA_256);
//        d.setNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");
//        d.setMethod("GET");
//        d.setUsername("Mufasa");
//        d.setPassword("Circle of Life");
//        d.setDigestUri("/dir/index.html");
//        d.setQop(QopOptions.AUTH);
//        d.setNonceCount("00000001");
//        d.setCnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
//        assertEquals(response, d.response());
//    }
}
