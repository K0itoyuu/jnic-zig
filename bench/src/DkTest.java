import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.StringEncrypt;
import master.koitoyuu.jnic.NumberEncrypt;

/**
 * Test class for verifying decode-key field isolation.
 *
 * After obfuscation:
 * - <clinit> should contain ldc2_w (decode_key values) + putstatic (_jnic$dk$N)
 * - Methods should use getstatic (_jnic$dk$N) instead of ldc2_w for decode_key
 * - DLL should NOT contain any decode_key long values
 *
 * Use Recaf to inspect:
 * 1. Check <clinit> for ldc2_w long constants → putstatic _jnic$dk$0, _jnic$dk$1...
 * 2. Check nativized methods only have getstatic references (no inline decode_key)
 * 3. Check private static long fields: _jnic$dk$0, _jnic$dk$1...
 */
@Native
@StringEncrypt
@NumberEncrypt
public class DkTest {
    private static final String GREETING = "Hello from DkTest";
    private static final int MAGIC = 42;
    private static final long BIG = 123456789012345L;
    private static final double PI = 3.14159265358979;

    public static void main(String[] args) {
        System.out.println(testString());
        System.out.println("int: " + testInt());
        System.out.println("long: " + testLong());
        System.out.println("double: " + testDouble());
        System.out.println("combined: " + testCombined());
        System.out.println("DkTest PASS");
    }

    public static String testString() {
        return GREETING;
    }

    public static int testInt() {
        return MAGIC + 100;
    }

    public static long testLong() {
        return BIG * 2;
    }

    public static double testDouble() {
        return PI * 2.0;
    }

    public static String testCombined() {
        int x = MAGIC;
        long y = BIG;
        double z = PI;
        return "x=" + x + " y=" + y + " z=" + String.format("%.5f", z);
    }
}
