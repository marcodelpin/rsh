package it.mdp.mrsh;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

/**
 * MrshUserService — Shizuku user-service implementation (bd rsh-a88j).
 *
 * Loaded by Shizuku via bindUserService(). Runs in the Shizuku-bridged
 * remote process, NOT in our app's main process. Auth depends on how
 * Shizuku itself was started:
 *   - root: uid=0 (Magisk)
 *   - adb:  uid=2000 shell (Wireless Debugging on Android 11+)
 *
 * Methods exposed here are reachable through ShizukuBridge -> binder.
 */
public class MrshUserService extends IUserService.Stub {

    private static final String TAG = "mrsh.user-svc";

    /** Required no-arg ctor for Shizuku loader. */
    public MrshUserService() {
        Log.i(TAG, "MrshUserService instantiated, uid=" + android.os.Process.myUid());
    }

    @Override
    public void destroy() {
        Log.i(TAG, "destroy() called, exiting");
        System.exit(0);
    }

    /**
     * Run an arbitrary command via ProcessBuilder. argv[0] is the program,
     * rest are args. stderr merged into stdout. Returns combined output.
     * Throws RuntimeException on launcher failure — caller (across binder)
     * sees a RemoteException.
     */
    @Override
    public String runCmd(String[] argv) {
        Log.i(TAG, "runCmd argv=" + Arrays.toString(argv));
        StringBuilder buf = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            drainInto(proc.getInputStream(), buf);
            int rc = proc.waitFor();
            buf.append("\n[rc=").append(rc).append("]");
            Log.i(TAG, "runCmd rc=" + rc + " out.length=" + buf.length());
        } catch (Throwable t) {
            Log.e(TAG, "runCmd failed", t);
            buf.append("\n[error: ")
               .append(t.getClass().getSimpleName())
               .append(": ")
               .append(t.getMessage())
               .append("]");
        }
        return buf.toString();
    }

    /**
     * Silent APK install via `pm install -r -t -d -i it.mdp.mrsh <path>`.
     * Returns exit code of pm (0 = success).
     *
     * pm install runs in system_server SELinux context which cannot read
     * /sdcard/* paths (sdcardfs MAC denial). When the source APK is under
     * /sdcard/* we first copy it to /data/local/tmp/ (shell-readable) and
     * pass that path to pm. We run as Shizuku-bridged uid (root or shell)
     * so the copy is permitted regardless of source location.
     */
    @Override
    public int installApk(String apkPath) {
        Log.i(TAG, "installApk path=" + apkPath);
        String targetPath = apkPath;
        java.io.File stagedTmp = null;
        try {
            if (apkPath.startsWith("/sdcard/")
                    || apkPath.startsWith("/storage/emulated/")
                    || apkPath.startsWith("/mnt/sdcard/")) {
                stagedTmp = new java.io.File("/data/local/tmp/mrsh-install-"
                        + System.currentTimeMillis() + ".apk");
                copyFile(new java.io.File(apkPath), stagedTmp);
                if (!stagedTmp.setReadable(true, false)) {
                    Log.w(TAG, "could not chmod a+r on " + stagedTmp);
                }
                targetPath = stagedTmp.getAbsolutePath();
                Log.i(TAG, "staged sdcard apk -> " + targetPath);
            }
        } catch (Throwable t) {
            Log.e(TAG, "stage to /data/local/tmp failed", t);
            return -2;
        }

        String[] argv = new String[] {
                "pm", "install",
                "-r",
                "-t",
                "-d",
                "-i", "it.mdp.mrsh",
                targetPath
        };
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder buf = new StringBuilder();
            drainInto(proc.getInputStream(), buf);
            int rc = proc.waitFor();
            Log.i(TAG, "installApk rc=" + rc + " output=" + buf.toString().trim());
            return rc;
        } catch (Throwable t) {
            Log.e(TAG, "installApk failed", t);
            return -1;
        } finally {
            if (stagedTmp != null && stagedTmp.exists()) {
                if (!stagedTmp.delete()) {
                    Log.w(TAG, "could not delete staged " + stagedTmp);
                }
            }
        }
    }

    private static void copyFile(java.io.File src, java.io.File dst) throws java.io.IOException {
        try (java.io.FileInputStream in = new java.io.FileInputStream(src);
             java.io.FileOutputStream out = new java.io.FileOutputStream(dst)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    private static void drainInto(InputStream is, StringBuilder sink) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = br.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (Throwable t) {
            Log.w(TAG, "drainInto: " + t.getMessage());
        }
    }
}
