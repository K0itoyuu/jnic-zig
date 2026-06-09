package master.koitoyuu.jnic;

import java.io.*;
import java.nio.file.*;

/**
 * Auto-extracts and loads the native library from JAR resources.
 * Called from <clinit> of protected classes.
 */
public class NativeLoader {
    private static volatile boolean loaded = false;

    public static synchronized void load() {
        if (loaded) return;
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            String libName;
            if (os.contains("win")) {
                libName = "jnic_native.dll";
            } else if (os.contains("mac") || os.contains("darwin")) {
                libName = "libjnic_native.dylib";
            } else {
                libName = "libjnic_native.so";
            }

            // Try to load from JAR resource
            String resourcePath = "/master/koitoyuu/jnic/" + libName;
            InputStream in = NativeLoader.class.getResourceAsStream(resourcePath);
            if (in == null) {
                // Fallback: try System.loadLibrary
                System.loadLibrary("jnic_native");
                loaded = true;
                return;
            }

            // Extract to temp directory
            Path tempDir = Files.createTempDirectory("jnic_");
            Path tempLib = tempDir.resolve(libName);
            Files.copy(in, tempLib, StandardCopyOption.REPLACE_EXISTING);
            in.close();

            // Load from temp path
            System.load(tempLib.toAbsolutePath().toString());

            // Schedule cleanup on JVM exit
            tempLib.toFile().deleteOnExit();
            tempDir.toFile().deleteOnExit();

            loaded = true;
        } catch (IOException e) {
            // Last resort fallback
            System.loadLibrary("jnic_native");
            loaded = true;
        }
    }
}
