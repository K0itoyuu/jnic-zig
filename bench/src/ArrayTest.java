import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.ArrayObfuscation;

@Native
@ArrayObfuscation
public class ArrayTest {
    // This array has 16 elements → should trigger blob encryption
    private static final int[] SBOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
    };

    private static final long[] KEYS = {
        0x0123456789ABCDEFL, 0xFEDCBA9876543210L,
        0xDEADBEEFCAFEBABEL, 0x1234567890ABCDEFL,
        0xABCDEF0123456789L, 0x9876543210FEDCBAL,
        0xCAFEBABEDEADBEEFL, 0x0FEDCBA987654321L
    };

    public static void main(String[] args) {
        int sum = 0;
        for (int v : SBOX) sum += v;
        System.out.println("SBOX sum: " + sum);

        long lsum = 0;
        for (long v : KEYS) lsum += v;
        System.out.println("KEYS sum: " + lsum);

        System.out.println("ArrayTest PASS");
    }
}
