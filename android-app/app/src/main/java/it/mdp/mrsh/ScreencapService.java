package it.mdp.mrsh;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.os.IBinder;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.WindowManager;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

/**
 * ScreencapService — foreground service hosting MediaProjection.
 *
 * Holds MediaProjection token across captures so the user grants consent only
 * once per session, not per-screenshot. Triggered actions:
 *   - ACTION_START_WITH_CONSENT: initialize with (result_code, result_data) from
 *     MediaProjectionManager consent dialog, then capture once with 'out' extra
 *   - ACTION_CAPTURE: capture immediately, write PNG to 'out' extra
 *
 * Foreground service required by Android 10+ for MediaProjection (PROJECT_MEDIA).
 *
 * bd: rsh-swxg.
 */
public class ScreencapService extends Service {

    private static final String TAG = "mrsh.scrcapsvc";
    private static final String CHANNEL_ID = "mrsh-screencap";
    private static final int NOTIFICATION_ID = 2;

    public static final String ACTION_START_WITH_CONSENT = "it.mdp.mrsh.SCREENCAP_START";
    public static final String ACTION_CAPTURE = "it.mdp.mrsh.SCREENCAP_NOW";

    private static volatile boolean running = false;
    public static boolean isRunning() {
        return running;
    }

    private MediaProjection projection;
    private int screenWidth;
    private int screenHeight;
    private int screenDensity;

    @Override
    public void onCreate() {
        super.onCreate();
        ensureChannel();
        startForeground(NOTIFICATION_ID, buildNotification("mrsh screencap ready"));

        DisplayMetrics dm = new DisplayMetrics();
        WindowManager wm = (WindowManager) getSystemService(Context.WINDOW_SERVICE);
        if (wm != null) {
            wm.getDefaultDisplay().getRealMetrics(dm);
        }
        screenWidth = dm.widthPixels > 0 ? dm.widthPixels : 1080;
        screenHeight = dm.heightPixels > 0 ? dm.heightPixels : 1920;
        screenDensity = dm.densityDpi > 0 ? dm.densityDpi : DisplayMetrics.DENSITY_DEFAULT;
        Log.i(TAG, "screen " + screenWidth + "x" + screenHeight + " dpi=" + screenDensity);
        running = true;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || intent.getAction() == null) {
            return START_STICKY;
        }
        String action = intent.getAction();
        String outPath = intent.getStringExtra("out");

        if (ACTION_START_WITH_CONSENT.equals(action)) {
            int code = intent.getIntExtra("result_code", -1);
            Intent data = intent.getParcelableExtra("result_data");
            if (data == null) {
                Log.e(TAG, "missing result_data on START_WITH_CONSENT");
                return START_STICKY;
            }
            try {
                MediaProjectionManager mpm = (MediaProjectionManager)
                        getSystemService(MEDIA_PROJECTION_SERVICE);
                projection = mpm.getMediaProjection(code, data);
                if (projection == null) {
                    Log.e(TAG, "getMediaProjection returned null");
                    return START_STICKY;
                }
                projection.registerCallback(new MediaProjection.Callback() {
                    @Override
                    public void onStop() {
                        Log.w(TAG, "MediaProjection stopped — service will need re-consent");
                        running = false;
                        projection = null;
                        stopSelf();
                    }
                }, null);
                Log.i(TAG, "MediaProjection initialized");
                if (outPath != null) {
                    captureAsync(outPath);
                }
            } catch (Exception e) {
                Log.e(TAG, "init failed", e);
            }
        } else if (ACTION_CAPTURE.equals(action)) {
            if (projection == null) {
                Log.e(TAG, "capture requested but no projection — restart via ScreencapActivity");
                return START_STICKY;
            }
            if (outPath != null) {
                captureAsync(outPath);
            }
        }
        return START_STICKY;
    }

    /**
     * Dispatch capture to a background thread — keeping main thread free
     * prevents ANR (5s wall-clock budget per Android). PNG encode of a
     * 1920x1080 frame can take 500ms-2s, polling for ImageReader frame
     * adds up to 1.5s — together easily exceeds the main-thread budget.
     */
    private void captureAsync(final String outPath) {
        Thread t = new Thread(() -> captureOnce(outPath), "mrsh-screencap-" + System.currentTimeMillis());
        t.setDaemon(true);
        t.start();
    }

    /**
     * Capture one frame to PNG file. Creates a fresh VirtualDisplay + ImageReader
     * per capture so we don't hold buffers across captures.
     */
    private void captureOnce(String outPath) {
        ImageReader reader = null;
        VirtualDisplay vd = null;
        try {
            reader = ImageReader.newInstance(screenWidth, screenHeight, PixelFormat.RGBA_8888, 2);
            vd = projection.createVirtualDisplay(
                    "mrsh-screencap",
                    screenWidth, screenHeight, screenDensity,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    reader.getSurface(),
                    null, null);

            // Poll for image — frame arrives within ~50-200ms.
            Image image = null;
            for (int i = 0; i < 30 && image == null; i++) {
                image = reader.acquireLatestImage();
                if (image == null) {
                    Thread.sleep(50);
                }
            }
            if (image == null) {
                Log.e(TAG, "no image after polling");
                return;
            }
            try {
                Bitmap bitmap = imageToBitmap(image);
                File out = new File(outPath);
                File parent = out.getParentFile();
                if (parent != null && !parent.exists()) {
                    parent.mkdirs();
                }
                try (BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(out))) {
                    bitmap.compress(Bitmap.CompressFormat.PNG, 90, os);
                }
                bitmap.recycle();
                Log.i(TAG, "captured " + out.length() + " bytes → " + outPath);
            } finally {
                image.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "captureOnce failed: " + e.getMessage(), e);
        } finally {
            if (vd != null) {
                try { vd.release(); } catch (Exception ignored) {}
            }
            if (reader != null) {
                try { reader.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Convert RGBA_8888 ImageReader.Image to Bitmap, handling row stride padding.
     */
    private Bitmap imageToBitmap(Image image) {
        Image.Plane[] planes = image.getPlanes();
        ByteBuffer buffer = planes[0].getBuffer();
        int pixelStride = planes[0].getPixelStride();
        int rowStride = planes[0].getRowStride();
        int rowPadding = rowStride - pixelStride * screenWidth;
        int width = screenWidth + rowPadding / pixelStride;
        Bitmap raw = Bitmap.createBitmap(width, screenHeight, Bitmap.Config.ARGB_8888);
        raw.copyPixelsFromBuffer(buffer);
        if (rowPadding == 0) {
            return raw;
        }
        Bitmap cropped = Bitmap.createBitmap(raw, 0, 0, screenWidth, screenHeight);
        raw.recycle();
        return cropped;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "service onDestroy");
        running = false;
        if (projection != null) {
            try { projection.stop(); } catch (Exception ignored) {}
            projection = null;
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "mrsh screencap", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Screen capture session held open for mrsh exec calls");
        nm.createNotificationChannel(ch);
    }

    private Notification buildNotification(String text) {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        return b.setContentTitle("mrsh screencap")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_camera)
                .setOngoing(true)
                .build();
    }
}
