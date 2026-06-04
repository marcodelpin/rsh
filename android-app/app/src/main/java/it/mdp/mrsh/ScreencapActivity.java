package it.mdp.mrsh;

import android.app.Activity;
import android.content.Intent;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

/**
 * ScreencapActivity — front-door for screen capture.
 *
 * Invocation:
 *   am start --user 0 -a it.mdp.mrsh.SCREENCAP --es out /sdcard/Download/x.png
 *
 * Flow:
 *   1) If ScreencapService is NOT alive: request MediaProjection consent via
 *      system dialog (user taps "Start now"), then start service with token.
 *      First capture happens automatically after consent.
 *   2) If service IS alive: forward capture request directly, no consent re-asked.
 *
 * Output path comes from 'out' intent extra (full path on /sdcard or app sandbox).
 * Default if missing: /sdcard/Download/mrsh-screencap-<ts>.png
 *
 * bd: rsh-swxg (absorb-B from rsh-gz0z — screencap endpoint).
 */
public class ScreencapActivity extends Activity {

    private static final String TAG = "mrsh.scrcap";
    private static final int REQ_MEDIA_PROJECTION = 2001;
    static volatile String pendingOutPath = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String outPath = getIntent() != null ? getIntent().getStringExtra("out") : null;
        if (outPath == null || outPath.isEmpty()) {
            outPath = "/sdcard/Download/mrsh-screencap-" + System.currentTimeMillis() + ".png";
        }
        Log.i(TAG, "request out=" + outPath);

        if (ScreencapService.isRunning()) {
            // Service alive: forward to it directly, no consent needed.
            Intent forward = new Intent(this, ScreencapService.class);
            forward.setAction(ScreencapService.ACTION_CAPTURE);
            forward.putExtra("out", outPath);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(forward);
            } else {
                startService(forward);
            }
            Toast.makeText(this, "mrsh screencap: capturing → " + outPath,
                    Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        // Service not alive: request MediaProjection consent.
        pendingOutPath = outPath;
        MediaProjectionManager mpm = (MediaProjectionManager)
                getSystemService(MEDIA_PROJECTION_SERVICE);
        if (mpm == null) {
            Toast.makeText(this, "mrsh screencap: MediaProjectionManager unavailable",
                    Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        Intent consent = mpm.createScreenCaptureIntent();
        startActivityForResult(consent, REQ_MEDIA_PROJECTION);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQ_MEDIA_PROJECTION) {
            super.onActivityResult(requestCode, resultCode, data);
            return;
        }
        if (resultCode != RESULT_OK || data == null) {
            Toast.makeText(this, "mrsh screencap: consent denied", Toast.LENGTH_LONG).show();
            Log.w(TAG, "consent denied resultCode=" + resultCode);
            pendingOutPath = null;
            finish();
            return;
        }
        Log.i(TAG, "consent granted, starting ScreencapService");
        Intent svc = new Intent(this, ScreencapService.class);
        svc.setAction(ScreencapService.ACTION_START_WITH_CONSENT);
        svc.putExtra("result_code", resultCode);
        svc.putExtra("result_data", data);
        svc.putExtra("out", pendingOutPath != null
                ? pendingOutPath
                : "/sdcard/Download/mrsh-screencap-" + System.currentTimeMillis() + ".png");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
        pendingOutPath = null;
        finish();
    }
}
