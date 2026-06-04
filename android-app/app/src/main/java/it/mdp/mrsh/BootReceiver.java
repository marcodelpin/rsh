package it.mdp.mrsh;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BOOT_COMPLETED receiver — launches MrshService as a foreground service so
 * the embedded mrsh native binary starts within seconds of phone boot.
 *
 * C1 stub: just logs the boot event and calls startForegroundService. C2 will
 * wire the actual supervise-and-restart loop inside MrshService.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "mrsh.boot";

    @Override
    public void onReceive(Context ctx, Intent intent) {
        String action = intent != null ? intent.getAction() : null;
        Log.i(TAG, "boot intent received: " + action);

        Intent svc = new Intent(ctx, MrshService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(svc);
        } else {
            ctx.startService(svc);
        }
    }
}
