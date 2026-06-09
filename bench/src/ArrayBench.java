import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.NumberEncrypt;
import master.koitoyuu.jnic.StringEncrypt;

@Native
@NumberEncrypt
@StringEncrypt
public class ArrayBench {
    // 16-element int array (blob encrypted, 1 JNI call)
    private static final int[] SBOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
    };

    // 32-element int array
    private static final int[] TABLE = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };

    // 16-element long array
    private static final long[] KEYS = {
        0x0123456789ABCDEFL, 0xFEDCBA9876543210L,
        0xDEADBEEFCAFEBABEL, 0x1234567890ABCDEFL,
        0xABCDEF0123456789L, 0x9876543210FEDCBAL,
        0xCAFEBABEDEADBEEFL, 0x0FEDCBA987654321L,
        0x1111111111111111L, 0x2222222222222222L,
        0x3333333333333333L, 0x4444444444444444L,
        0x5555555555555555L, 0x6666666666666666L,
        0x7777777777777777L, 0x8888888888888888L
    };

    // Regular int constant (per-element encrypted)
    private static final int SECRET = 42;

    public static void main(String[] args) {
        // Warmup
        for (int w = 0; w < 100; w++) { compute(); }

        long t0 = System.nanoTime();
        long result = 0;
        for (int i = 0; i < 1000000; i++) {
            result += compute();
        }
        long t1 = System.nanoTime();

        long ms = (t1 - t0) / 1000000;
        System.out.print("Array access loop (1M): ");
        System.out.print(ms);
        System.out.print("ms  r=");
        System.out.println(result);

        // Verify correctness
        int sboxSum = 0;
        for (int v : SBOX) sboxSum += v;
        System.out.print("SBOX sum: ");
        System.out.println(sboxSum);

        int tableSum = 0;
        for (int v : TABLE) tableSum += v;
        System.out.print("TABLE sum: ");
        System.out.println(tableSum);

        long keySum = 0;
        for (long v : KEYS) keySum += v;
        System.out.print("KEYS sum: ");
        System.out.println(keySum);

        System.out.print("SECRET: ");
        System.out.println(SECRET);
    }

    private static long compute() {
        long sum = 0;
        for (int i = 0; i < 16; i++) {
            sum += SBOX[i] ^ TABLE[i] ^ KEYS[i];
        }
        return sum + SECRET;
    }
}
