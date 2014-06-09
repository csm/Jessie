package org.metastatic.jessie.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.metastatic.jessie.provider.InputSecurityParameters;
import org.metastatic.jessie.provider.Util;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class TestPaddingCheck
{
    @Test
    public void testBasicGoodPadding() throws Exception
    {
        for (int fraglen : asList(16, 64, 128, 192, 256, 320, 384))
        {
            byte[] fragment = new byte[fraglen];
            Arrays.fill(fragment, (byte) 0xAB);
            List<Long> times = new ArrayList<>();
            for (int padlen = 1; padlen < Math.min(256, fraglen - 1); padlen++)
            {
                Arrays.fill(fragment, fraglen - padlen, fraglen, (byte) padlen);
                ByteBuffer buffer = ByteBuffer.wrap(fragment);
                long begin = System.nanoTime();
                boolean result = InputSecurityParameters.checkPadding(fraglen, buffer, padlen);
                long end = System.nanoTime();
                times.add(end - begin);
                assertFalse(Util.hexDump(buffer), result);
            }
            double s0 = (double) times.size();
            double s1 = times.stream().mapToDouble(l -> l).sum();
            double s2 = times.stream().mapToDouble(l -> l * l).sum();
            System.out.printf("for %d: average: %s max: %s min: %s dev:%f%n", fraglen,
                    times.stream().mapToLong(l -> l).average().getAsDouble(),
                    times.stream().mapToLong(l -> l).max().getAsLong(),
                    times.stream().mapToLong(l -> l).min().getAsLong(),
                    Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        }
    }

    @Test
    public void testBadPadding() throws Exception
    {
        for (int fraglen : asList(64, 128, 192, 256, 320, 384))
        {
            byte[] fragment = new byte[fraglen];
            Arrays.fill(fragment, (byte) 0xAB);
            List<Long> times = new ArrayList<>();
            for (int padlen = 1; padlen < Math.min(256, fraglen - 1); padlen++)
            {
                for (int bad = 0; bad < padlen; bad++) {
                    Arrays.fill(fragment, fraglen - padlen, fraglen, (byte) padlen);
                    fragment[fraglen - padlen + bad] = (byte) ~padlen;
                    ByteBuffer buffer = ByteBuffer.wrap(fragment);
                    long begin = System.nanoTime();
                    boolean result = InputSecurityParameters.checkPadding(fraglen, buffer, padlen);
                    long end = System.nanoTime();
                    times.add(end - begin);
                    assertTrue(Util.hexDump(buffer), result);
                }
            }
            double s0 = (double) times.size();
            double s1 = times.stream().mapToDouble(l -> l).sum();
            double s2 = times.stream().mapToDouble(l -> l * l).sum();
            System.out.printf("for %d: average: %s max: %s min: %s dev:%f%n", fraglen,
                    times.stream().mapToLong(l -> l).average().getAsDouble(),
                    times.stream().mapToLong(l -> l).max().getAsLong(),
                    times.stream().mapToLong(l -> l).min().getAsLong(),
                    Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        }
    }
}
