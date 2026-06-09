package pack.tests.bench;

import master.koitoyuu.jnic.Native;

@Native
public class PureBench {
    // Pure computation — no method calls, no objects, just arithmetic
    public static int intArith(int n) {
        int sum = 0;
        for (int i = 0; i < n; i++) {
            sum += i * 3 - i / 2 + i % 7;
        }
        return sum;
    }

    public static long longArith(long n) {
        long sum = 0;
        for (long i = 0; i < n; i++) {
            sum += i * 7 - i / 3;
        }
        return sum;
    }

    public static int bitwise(int n) {
        int bits = 0xDEADBEEF;
        for (int i = 0; i < n; i++) {
            bits = (bits << 1) ^ (bits >> 3) ^ i;
        }
        return bits;
    }

    public static int nested(int n) {
        int sum = 0;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                sum += i * j;
            }
        }
        return sum;
    }

    public static void main(String[] args) {
        long t1 = System.currentTimeMillis();
        int r1 = intArith(10000000);
        t1 = System.currentTimeMillis() - t1;

        long t2 = System.currentTimeMillis();
        long r2 = longArith(5000000);
        t2 = System.currentTimeMillis() - t2;

        long t3 = System.currentTimeMillis();
        int r3 = bitwise(10000000);
        t3 = System.currentTimeMillis() - t3;

        long t4 = System.currentTimeMillis();
        int r4 = nested(1000);
        t4 = System.currentTimeMillis() - t4;

        System.out.println("Int arith:  " + t1 + "ms  r=" + r1);
        System.out.println("Long arith: " + t2 + "ms  r=" + r2);
        System.out.println("Bitwise:    " + t3 + "ms  r=" + r3);
        System.out.println("Nested:     " + t4 + "ms  r=" + r4);
        System.out.println("Total: " + (t1+t2+t3+t4) + "ms");
    }
}
