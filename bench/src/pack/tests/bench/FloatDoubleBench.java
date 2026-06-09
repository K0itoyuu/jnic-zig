package pack.tests.bench;

import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.NumberEncrypt;

@Native
@NumberEncrypt
public class FloatDoubleBench {
    public static float floatArith(int n) {
        float sum = 0.0f;
        for (int i = 0; i < n; i++) {
            float x = (float) i;
            sum += x * 1.25f - x / 3.5f + 0.75f;
        }
        return sum;
    }

    public static double doubleArith(int n) {
        double sum = 0.0d;
        for (int i = 0; i < n; i++) {
            double x = (double) i;
            sum += x * 0.99d - x / 7.25d + 0.125d;
        }
        return sum;
    }

    public static long runAll() {
        System.out.println("=== FloatDoubleBench (Native + NumberEncrypt) ===");

        long start = System.currentTimeMillis();
        float fr = floatArith(10000000);
        long ft = System.currentTimeMillis() - start;

        start = System.currentTimeMillis();
        double dr = doubleArith(10000000);
        long dt = System.currentTimeMillis() - start;

        System.out.println("Float arith (10M):  " + ft + "ms  r=" + fr);
        System.out.println("Double arith (10M): " + dt + "ms  r=" + dr);
        System.out.println("Total: " + (ft + dt) + "ms");
        return ft + dt;
    }

    public static void main(String[] args) {
        System.loadLibrary("yurijvm_native");
        runAll();
    }
}
