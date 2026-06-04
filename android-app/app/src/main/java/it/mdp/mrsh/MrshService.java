package it.mdp.mrsh;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * MrshService — foreground service that spawns and supervises a long-running
 * mrsh native process (libmrsh.so in nativeLibraryDir) for the lifetime of
 * the device boot. On exit it restarts with exponential backoff.
 *
 * Wired by BootReceiver (BOOT_COMPLETED → startForegroundService).
 *
 * bd: rsh-10qh (parent rsh-b3ir).
 */
public class MrshService extends Service {
    private static final String TAG = "mrsh.svc";
    private static final String CHANNEL_ID = "mrsh-foreground";
    private static final int NOTIFICATION_ID = 1;

    private static final int MRSH_PORT = 8822;
    private static final String RENDEZVOUS_SERVER = "rendezvous.example.com:21116";
    private static final String RENDEZVOUS_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // workstation mrsh-client pubkey, pre-seeded so workstation reaches new
    // devices out of the box. More keys can be added later via the live
    // server using `mrsh keys add` from any already-authorized client.
    private static final String SEED_AUTHORIZED_KEY =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9EEPIMrnO54PY+F8T5OsoEqlkfxjQ26JdPGEwguuTo mrsh-client\n";

    private static final long BACKOFF_INITIAL_MS = 1000;
    private static final long BACKOFF_MAX_MS = 60_000;

    private volatile boolean shouldRun = false;
    private volatile Process current;
    private Thread superviseThread;
    private PowerManager.WakeLock wakeLock;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "service onCreate");
        ensureChannel();
        startForeground(NOTIFICATION_ID, buildNotification("starting…"));

        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm != null) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "mrsh:server");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "service onStartCommand");
        // Pre-warm Shizuku user-service binding in background — Note3-class
        // hardware takes ~30s for the bindUserService callback to deliver,
        // and we want install requests to hit a warm binding. No-op when
        // Shizuku absent or permission not granted. rsh-a88j F3.2.
        ShizukuBridge.warmUp();
        if (!shouldRun) {
            shouldRun = true;
            try {
                bootstrapConfig();
            } catch (Exception e) {
                Log.e(TAG, "bootstrap failed", e);
            }
            superviseThread = new Thread(this::superviseLoop, "mrsh-supervise");
            superviseThread.setDaemon(false);
            superviseThread.start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "service onDestroy");
        shouldRun = false;
        Process p = current;
        if (p != null) {
            p.destroy();
        }
        if (superviseThread != null) {
            superviseThread.interrupt();
        }
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ─── Supervise loop ─────────────────────────────────────────────────

    private void superviseLoop() {
        long backoff = BACKOFF_INITIAL_MS;
        while (shouldRun) {
            updateNotification("starting mrsh");
            Process p = spawnMrsh();
            if (p == null) {
                Log.e(TAG, "spawn failed, backoff " + backoff + "ms");
                updateNotification("spawn failed, retry in " + (backoff / 1000) + "s");
                if (!sleepInterruptible(backoff)) break;
                backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
                continue;
            }
            current = p;
            long pid = -1;
            try { pid = pidOf(p); } catch (Exception ignored) {}
            Log.i(TAG, "mrsh started pid=" + pid);
            updateNotification("running pid=" + pid + " :" + MRSH_PORT);

            int exit;
            try {
                exit = p.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Log.i(TAG, "supervise interrupted, terminating mrsh");
                p.destroy();
                break;
            } finally {
                current = null;
            }

            if (!shouldRun) break;

            if (exit == 0) {
                Log.w(TAG, "mrsh exited cleanly (0), restarting after " + BACKOFF_INITIAL_MS + "ms");
                backoff = BACKOFF_INITIAL_MS;
            } else {
                Log.w(TAG, "mrsh exited code=" + exit + ", restarting after " + backoff + "ms");
            }
            updateNotification("restart in " + (backoff / 1000) + "s (exit=" + exit + ")");
            if (!sleepInterruptible(backoff)) break;
            backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
        }
        Log.i(TAG, "supervise loop exiting");
        updateNotification("stopped");
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private Process spawnMrsh() {
        File binary = new File(getApplicationInfo().nativeLibraryDir, "libmrsh.so");
        if (!binary.exists() || !binary.canExecute()) {
            Log.e(TAG, "libmrsh.so missing or not executable at " + binary.getAbsolutePath());
            return null;
        }
        File home = getFilesDir();
        File logDir = getExternalFilesDir(null);
        if (logDir == null) logDir = home;
        File logFile = new File(logDir, "mrsh.log");

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    binary.getAbsolutePath(),
                    "--console",
                    "-p", String.valueOf(MRSH_PORT)
            );
            pb.environment().put("HOME", home.getAbsolutePath());
            pb.environment().put("TMPDIR", getCacheDir().getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.appendTo(logFile));
            return pb.start();
        } catch (IOException e) {
            Log.e(TAG, "ProcessBuilder.start() failed", e);
            return null;
        }
    }

    private long pidOf(Process p) {
        // Process.pid() is Java 9+; we target Java 8 source/target compat so
        // it is not visible at compile time. Reflection lookup works on all
        // Android API levels — the framework keeps a `pid` int field on
        // ProcessImpl. Falls back to -1 if the field is renamed in a future
        // release.
        try {
            java.lang.reflect.Field f = p.getClass().getDeclaredField("pid");
            f.setAccessible(true);
            return f.getInt(p);
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private boolean sleepInterruptible(long ms) {
        try {
            Thread.sleep(ms);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // ─── Bootstrap (first boot) ─────────────────────────────────────────

    private void bootstrapConfig() throws IOException {
        File mrshDir = new File(getFilesDir(), ".mrsh");
        if (!mrshDir.exists() && !mrshDir.mkdirs()) {
            throw new IOException("failed to create " + mrshDir);
        }

        File configFile = new File(mrshDir, "config");
        if (!configFile.exists()) {
            long deviceId = deriveDeviceId();
            String body = "DeviceID " + deviceId + "\n"
                    + "RendezvousServer " + RENDEZVOUS_SERVER + "\n"
                    + "RendezvousKey " + RENDEZVOUS_KEY + "\n";
            writeFile(configFile, body);
            Log.i(TAG, "wrote default config DeviceID=" + deviceId);
        }

        File authKeys = new File(mrshDir, "authorized_keys");
        if (!authKeys.exists()) {
            writeFile(authKeys, SEED_AUTHORIZED_KEY);
            Log.i(TAG, "seeded authorized_keys with workstation pubkey");
        }
        // ed25519 host key: the mrsh binary auto-generates id_ed25519 on first
        // listen if absent (verified empirically on M20 via Termux bootstrap
        // @2026-05-11, upd-clv).
    }

    private long deriveDeviceId() {
        String aid;
        try {
            aid = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        } catch (Throwable e) {
            aid = null;
        }
        long base;
        if (aid == null || aid.isEmpty()) {
            base = Build.SERIAL != null ? Build.SERIAL.hashCode() : System.nanoTime();
        } else {
            base = 0L;
            for (int i = 0; i < aid.length(); i++) {
                base = base * 31 + aid.charAt(i);
            }
        }
        long m = (base & 0x7FFFFFFFFFFFFFFFL) % 900_000_000L + 100_000_000L;
        return m;
    }

    private void writeFile(File f, String content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }
        if (!f.setReadable(true, true) || !f.setWritable(true, true)) {
            Log.w(TAG, "perm set partial on " + f);
        }
    }

    // ─── Notification plumbing ──────────────────────────────────────────

    private void ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "mrsh server",
                    NotificationManager.IMPORTANCE_LOW
            );
            ch.setDescription("Background mrsh server running on this device");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification(String text) {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        return b
                .setContentTitle("mrsh server")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_notification)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .build();
    }

    private void updateNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.notify(NOTIFICATION_ID, buildNotification(text));
    }
}
