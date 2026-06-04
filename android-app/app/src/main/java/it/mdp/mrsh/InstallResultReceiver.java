package it.mdp.mrsh;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.util.Log;
import android.widget.Toast;

/**
 * InstallResultReceiver — handles PackageInstaller session status callbacks.
 *
 * Triggered async after InstallActivity.session.commit(): the system writes
 * STATUS extra (SUCCESS / PENDING_USER_ACTION / FAILURE) to this receiver.
 * If PENDING_USER_ACTION, EXTRA_INTENT contains the system Install confirm dialog.
 *
 * bd: rsh-ol1u (absorb-A: APK install endpoint).
 */
public class InstallResultReceiver extends BroadcastReceiver {

    private static final String TAG = "mrsh.installres";

    @Override
    public void onReceive(Context context, Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS,
                PackageInstaller.STATUS_FAILURE);
        String msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
        int sessionId = intent.getIntExtra("session_id", -1);
        String apkPath = intent.getStringExtra("apk_path");

        switch (status) {
            case PackageInstaller.STATUS_PENDING_USER_ACTION:
                // System needs user to confirm — launch the supplied confirm Intent.
                Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                if (confirm != null) {
                    confirm.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    try {
                        context.startActivity(confirm);
                        Log.i(TAG, "session=" + sessionId + " confirm dialog launched");
                    } catch (Exception e) {
                        Log.e(TAG, "confirm dialog launch failed", e);
                    }
                }
                break;
            case PackageInstaller.STATUS_SUCCESS:
                Log.i(TAG, "session=" + sessionId + " SUCCESS apk=" + apkPath);
                Toast.makeText(context, "mrsh install: SUCCESS " + apkPath,
                        Toast.LENGTH_SHORT).show();
                break;
            default:
                Log.w(TAG, "session=" + sessionId + " status=" + status + " msg=" + msg);
                Toast.makeText(context, "mrsh install failed: status=" + status + " " + msg,
                        Toast.LENGTH_LONG).show();
                break;
        }
    }
}
