package org.metastatic.jessie.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.metastatic.jessie.provider.InputSecurityParameters;
import org.metastatic.jessie.provider.Util;

import static java.util.Arrays.asList;
import static org.junit.Assert.*;


public class TestPaddingCheck
{
    @Test
    public void testBasicGoodPadding() throws Exception
    {
        for (int fraglen : asList(16, 64, 128, 192, 256, 320, 384))
        {
            byte[] fragment = new byte[fraglen];
            List<Long> times = new ArrayList<>();
            for (int padlen = 1; padlen < Math.min(256, fraglen - 1); padlen++)
            {
                Arrays.fill(fragment, (byte) ~padlen);
                Arrays.fill(fragment, fraglen - padlen - 1, fraglen, (byte) padlen);
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
            List<Long> times = new ArrayList<>();
            for (int padlen = 1; padlen < Math.min(256, fraglen - 1); padlen++)
            {
                for (int bad = 0; bad < padlen; bad++) {
                    Arrays.fill(fragment, (byte) ~padlen);
                    Arrays.fill(fragment, fraglen - padlen - 1, fraglen, (byte) padlen);
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

    @Test
    public void testVariedPatterns() throws Exception {
        byte[] fragment1 = Util.toByteArray("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead0101");
        byte[] fragment2 = Util.toByteArray("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assertEquals(256, fragment1.length);
        List<Long> times1 = new ArrayList<>();
        List<Long> times2 = new ArrayList<>();
        for (int i = 0; i < 10000; i++)
        {
            long begin = System.nanoTime();
            assertFalse(Util.toHexString(fragment1), InputSecurityParameters.checkPadding(fragment1.length, ByteBuffer.wrap(fragment1), 1));
            long end = System.nanoTime();
            if (i > 0)
                times1.add(end - begin);
            begin = System.nanoTime();
            assertFalse(Util.toHexString(fragment2), InputSecurityParameters.checkPadding(fragment2.length, ByteBuffer.wrap(fragment2), 255));
            end = System.nanoTime();
            if (i > 0)
                times2.add(end - begin);
        }

        Collections.sort(times1);
        double s0 = (double) times1.size();
        double s1 = times1.stream().mapToDouble(l -> l).sum();
        double s2 = times1.stream().mapToDouble(l -> l * l).sum();
        System.out.printf("for minimal padding: average: %s max: %s min: %s dev:%f%n",
                times1.stream().mapToLong(l -> l).average().getAsDouble(),
                times1.stream().mapToLong(l -> l).max().getAsLong(),
                times1.stream().mapToLong(l -> l).min().getAsLong(),
                Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        System.out.printf("bottom 5: %s%n   top 5: %s%n",
                times1.subList(0, 5), times1.subList(times1.size() - 5, times1.size()));
        Collections.sort(times2);
        s0 = (double) times2.size();
        s1 = times2.stream().mapToDouble(l -> l).sum();
        s2 = times2.stream().mapToDouble(l -> l * l).sum();
        System.out.printf("for maximal padding: average: %s max: %s min: %s dev:%f%n",
                times2.stream().mapToLong(l -> l).average().getAsDouble(),
                times2.stream().mapToLong(l -> l).max().getAsLong(),
                times2.stream().mapToLong(l -> l).min().getAsLong(),
                Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        System.out.printf("bottom 5: %s%n   top 5: %s%n",
                times1.subList(0, 5), times2.subList(times1.size() - 5, times2.size()));
    }

    @Test
    public void testVariedInvalidPatterns() throws Exception {
        byte[] fragment1 = Util.toByteArray("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadfe01");
        byte[] fragment2 = Util.toByteArray("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assertEquals(256, fragment1.length);
        List<Long> times1 = new ArrayList<>();
        List<Long> times2 = new ArrayList<>();
        for (int i = 0; i < 10000; i++)
        {
            long begin = System.nanoTime();
            assertTrue(Util.toHexString(fragment1), InputSecurityParameters.checkPadding(fragment1.length, ByteBuffer.wrap(fragment1), 1));
            long end = System.nanoTime();
            if (i > 0)
                times1.add(end - begin);
            begin = System.nanoTime();
            assertTrue(Util.toHexString(fragment2), InputSecurityParameters.checkPadding(fragment2.length, ByteBuffer.wrap(fragment2), 255));
            end = System.nanoTime();
            if (i > 0)
                times2.add(end - begin);
        }

        Collections.sort(times1);
        double s0 = (double) times1.size();
        double s1 = times1.stream().mapToDouble(l -> l).sum();
        double s2 = times1.stream().mapToDouble(l -> l * l).sum();
        System.out.printf("for minimal padding: average: %s max: %s min: %s dev:%f%n",
                times1.stream().mapToLong(l -> l).average().getAsDouble(),
                times1.stream().mapToLong(l -> l).max().getAsLong(),
                times1.stream().mapToLong(l -> l).min().getAsLong(),
                Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        System.out.printf("bottom 5: %s%n   top 5: %s%n",
                times1.subList(0, 5), times1.subList(times1.size() - 5, times1.size()));
        Collections.sort(times2);
        s0 = (double) times2.size();
        s1 = times2.stream().mapToDouble(l -> l).sum();
        s2 = times2.stream().mapToDouble(l -> l * l).sum();
        System.out.printf("for maximal padding: average: %s max: %s min: %s dev:%f%n",
                times2.stream().mapToLong(l -> l).average().getAsDouble(),
                times2.stream().mapToLong(l -> l).max().getAsLong(),
                times2.stream().mapToLong(l -> l).min().getAsLong(),
                Math.sqrt((s0 * s2 - s1 * s1)/(s0 * (s0 - 1))));
        System.out.printf("bottom 5: %s%n   top 5: %s%n",
                times1.subList(0, 5), times2.subList(times1.size() - 5, times2.size()));
    }
}
