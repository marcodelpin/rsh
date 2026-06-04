package it.mdp.mrsh;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageInstaller;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * InstallActivity — APK install dispatcher.
 *
 * Triggered via:
 *   am start -a it.mdp.mrsh.INSTALL_APK --es apk /sdcard/Download/file.apk
 *
 * Flow:
 *   1) Read 'apk' extra from intent
 *   2) Open PackageInstaller.Session, stream APK bytes in
 *   3) commit(IntentSender) → system shows Install dialog
 *   4) User taps Install → PackageInstaller does the install
 *   5) InstallResultReceiver gets the broadcast with status
 *
 * This obsoletes mdp-updater's APK install path for mrsh-android self-updates.
 *
 * bd: rsh-ol1u (absorb-A: APK install endpoint), rsh-w52b (info page bumped 0.1.6).
 */
public class InstallActivity extends Activity {

    private static final String TAG = "mrsh.install";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        String apkPath = intent != null ? intent.getStringExtra("apk") : null;
        if (apkPath == null || apkPath.isEmpty()) {
            Toast.makeText(this, "mrsh install: missing 'apk' extra", Toast.LENGTH_LONG).show();
            Log.e(TAG, "missing 'apk' extra");
            finish();
            return;
        }

        File apkFile = new File(apkPath);
        if (!apkFile.exists() || !apkFile.isFile() || !apkFile.canRead()) {
            String msg = "mrsh install: cannot read " + apkPath;
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
            Log.e(TAG, msg);
            finish();
            return;
        }

        // Prefer Shizuku silent-install path (rsh-a88j) when the bridge is
        // ready (service running + permission granted). Falls back to the
        // PackageInstaller user-dialog path on any failure or absence.
        if (ShizukuBridge.isReady()) {
            try {
                int rc = ShizukuBridge.install(apkFile.getAbsolutePath());
                Log.i(TAG, "shizuku install rc=" + rc);
                if (rc == 0) {
                    Toast.makeText(this,
                            "mrsh install: silent OK (shizuku) " + apkFile.getName(),
                            Toast.LENGTH_SHORT).show();
                    finish();
                    return;
                }
                Log.w(TAG, "shizuku install non-zero rc, falling back to PackageInstaller");
            } catch (Exception e) {
                Log.w(TAG, "shizuku install threw, falling back: " + e.getMessage(), e);
            }
        } else if (ShizukuBridge.hasService()) {
            // Service is up but we don't hold permission yet — request it
            // (user grants once via Shizuku Manager dialog, then subsequent
            // installs go through silently).
            ShizukuBridge.requestPermission();
            Log.i(TAG, "shizuku service present, permission requested — fall back this round");
        }

        try {
            installApk(apkFile);
            Toast.makeText(this, "mrsh install: dialog opening for " + apkFile.getName(),
                    Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Log.e(TAG, "install failed: " + e.getMessage(), e);
            Toast.makeText(this, "mrsh install error: " + e.getClass().getSimpleName(),
                    Toast.LENGTH_LONG).show();
        }
        finish();
    }

    /**
     * Stream an APK file through PackageInstaller.Session and commit.
     * commit() returns asynchronously — system displays Install dialog,
     * user confirms, install completes, InstallResultReceiver gets status.
     */
    private void installApk(File apkFile) throws Exception {
        PackageInstaller pi = getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(null); // detected from APK
        int sessionId = pi.createSession(params);
        Log.i(TAG, "session=" + sessionId + " apk=" + apkFile.getAbsolutePath()
                + " size=" + apkFile.length());

        PackageInstaller.Session session = pi.openSession(sessionId);
        try {
            try (OutputStream out = session.openWrite(apkFile.getName(), 0, apkFile.length());
                 InputStream in = new FileInputStream(apkFile)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                long total = 0;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    total += n;
                }
                session.fsync(out);
                Log.i(TAG, "session=" + sessionId + " wrote " + total + " bytes");
            }

            // Build commit IntentSender pointing at InstallResultReceiver.
            Intent receiverIntent = new Intent(this, InstallResultReceiver.class);
            receiverIntent.putExtra("apk_path", apkFile.getAbsolutePath());
            receiverIntent.putExtra("session_id", sessionId);
            // FLAG_MUTABLE required for PackageInstaller status extras (Android 12+).
            int flags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                flags |= PendingIntent.FLAG_MUTABLE;
            }
            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                    this, sessionId, receiverIntent, flags);
            IntentSender statusReceiver = pendingIntent.getIntentSender();

            session.commit(statusReceiver);
            Log.i(TAG, "session=" + sessionId + " commit dispatched");
        } finally {
            session.close();
        }
    }
}
