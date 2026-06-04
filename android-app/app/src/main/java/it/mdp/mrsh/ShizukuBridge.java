package it.mdp.mrsh;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import rikka.shizuku.Shizuku;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * ShizukuBridge — Shizuku user-service bridge (bd rsh-a88j absorb-D).
 *
 * Shizuku v13.x removed the direct `newProcess()` shortcut. Privileged
 * commands now go through a user-service that we bind into the
 * Shizuku-bridged remote process. This bridge wraps the bind/invoke flow:
 *
 *   1) check service alive + permission (hasService / isReady)
 *   2) request permission interactively if missing (requestPermission)
 *   3) bind MrshUserService via Shizuku.bindUserService(args, conn)
 *   4) once bound, call methods (runCmd / installApk) through the binder
 *
 * Auth mode depends on how Shizuku was started:
 *   - root: uid=0 (Magisk)
 *   - adb:  uid=2000 shell (Wireless Debugging Android 11+)
 *
 * When Shizuku is absent or denied, isReady() returns false and callers
 * fall back to the PackageInstaller user-prompt path
 * (InstallActivity installApk).
 */
public final class ShizukuBridge {

    private static final String TAG = "mrsh.shizuku";
    public static final int REQUEST_PERMISSION_CODE = 0x5152; // "SQ"

    /** UserService version — bumped whenever AIDL surface changes. */
    private static final int USER_SERVICE_VERSION = 1;

    /** How long we wait for bindUserService to complete (ms). Cold start
     *  empirically takes ~30s on Note3 hlte (Shizuku v13 binder callback
     *  delivery latency is significant on older hardware). 60s budget to
     *  avoid races; subsequent calls hit cached binding instantly. */
    private static final long BIND_TIMEOUT_MS = 60_000L;

    /** Cached bound interface (null when not bound). */
    private static volatile IUserService boundService = null;

    /** Sync primitive for the bind callback. */
    private static volatile CountDownLatch bindLatch = null;

    private static final Shizuku.UserServiceArgs USER_SERVICE_ARGS = new Shizuku.UserServiceArgs(
            new ComponentName("it.mdp.mrsh", MrshUserService.class.getName()))
            .daemon(false)
            .processNameSuffix("user-svc")
            .debuggable(false)
            .version(USER_SERVICE_VERSION);

    private static final ServiceConnection CONNECTION = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            if (binder == null || !binder.pingBinder()) {
                Log.w(TAG, "onServiceConnected: dead binder");
                boundService = null;
            } else {
                boundService = IUserService.Stub.asInterface(binder);
                Log.i(TAG, "user-service bound");
            }
            CountDownLatch l = bindLatch;
            if (l != null) l.countDown();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.i(TAG, "user-service disconnected");
            boundService = null;
        }
    };

    private ShizukuBridge() {}

    /** Shizuku binder is reachable on the device. */
    public static boolean hasService() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Fully ready: binder up AND app has permission to invoke privileged ops.
     */
    public static boolean isReady() {
        try {
            if (!Shizuku.pingBinder()) return false;
            if (Shizuku.isPreV11()) return false;
            return Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            Log.w(TAG, "isReady check failed: " + t.getClass().getSimpleName()
                    + " " + t.getMessage());
            return false;
        }
    }

    /**
     * Pre-warm the user-service bind in the background. Call from a long-lived
     * context (MrshService.onStartCommand or BootReceiver) at app start so the
     * binding is ready before the user invokes install — avoids the ~30s cold
     * start cost on Note3-class hardware. Idempotent + no-op if already bound
     * or Shizuku unavailable.
     */
    public static void warmUp() {
        new Thread(() -> {
            try {
                if (!isReady()) {
                    Log.i(TAG, "warmUp: shizuku not ready, skip");
                    return;
                }
                Log.i(TAG, "warmUp: triggering bind in background");
                IUserService svc = getOrBind();
                if (svc != null) {
                    Log.i(TAG, "warmUp: bound OK");
                } else {
                    Log.w(TAG, "warmUp: bind returned null");
                }
            } catch (Throwable t) {
                Log.w(TAG, "warmUp threw: " + t.getMessage());
            }
        }, "shizuku-warmup").start();
    }

    /** Trigger permission grant flow (asynchronous via listener). */
    public static boolean requestPermission() {
        try {
            if (!Shizuku.pingBinder()) return false;
            Shizuku.requestPermission(REQUEST_PERMISSION_CODE);
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "requestPermission failed: " + t.getMessage());
            return false;
        }
    }

    /**
     * Get the bound IUserService, binding it first if needed. Returns null
     * on bind failure or timeout. Synchronous — blocks up to BIND_TIMEOUT_MS.
     */
    private static IUserService getOrBind() {
        IUserService svc = boundService;
        if (svc != null) {
            try {
                if (svc.asBinder().pingBinder()) return svc;
            } catch (Throwable t) {
                Log.w(TAG, "stale bound service, rebinding");
            }
            boundService = null;
        }
        if (!isReady()) {
            Log.w(TAG, "getOrBind: not ready");
            return null;
        }
        CountDownLatch l = new CountDownLatch(1);
        bindLatch = l;
        try {
            Shizuku.bindUserService(USER_SERVICE_ARGS, CONNECTION);
        } catch (Throwable t) {
            Log.w(TAG, "bindUserService threw: " + t.getMessage(), t);
            return null;
        }
        try {
            if (!l.await(BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Log.w(TAG, "bindUserService timeout");
                return null;
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return null;
        }
        return boundService;
    }

    /**
     * Run a command via Shizuku user-service. argv[0] is the program.
     * Returns combined stdout+stderr (terminated with `[rc=N]` marker).
     * Throws IOException on bind failure or binder error.
     */
    public static String runCmd(String[] argv) throws IOException {
        IUserService svc = getOrBind();
        if (svc == null) throw new IOException("Shizuku user-service unavailable");
        try {
            return svc.runCmd(argv);
        } catch (RemoteException re) {
            throw new IOException("Shizuku binder runCmd failed: " + re.getMessage(), re);
        }
    }

    /**
     * Silent APK install via Shizuku user-service. Returns exit code of pm
     * (0 = success). Throws IOException on bind failure or binder error.
     */
    public static int install(String apkPath) throws IOException {
        IUserService svc = getOrBind();
        if (svc == null) throw new IOException("Shizuku user-service unavailable");
        try {
            return svc.installApk(apkPath);
        } catch (RemoteException re) {
            throw new IOException("Shizuku binder installApk failed: " + re.getMessage(), re);
        }
    }

    /** Drop the bound service (e.g. on shutdown / process tear-down). */
    public static void unbind() {
        try {
            if (boundService != null) {
                Shizuku.unbindUserService(USER_SERVICE_ARGS, CONNECTION, true);
            }
        } catch (Throwable t) {
            Log.w(TAG, "unbind: " + t.getMessage());
        }
        boundService = null;
    }
}
