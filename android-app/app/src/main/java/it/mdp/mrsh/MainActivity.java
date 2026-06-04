package it.mdp.mrsh;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;

/**
 * MainActivity — launcher entrypoint + info dashboard.
 *
 * Purposes:
 *   1) Provide LAUNCHER intent-filter so APK ships an icon (Android requires
 *      this to exit "stopped" state so BOOT_COMPLETED is delivered).
 *   2) Start MrshService immediately on first launch.
 *   3) Request storage permissions (rsh-viro).
 *   4) Display rich info dashboard (rsh-w52b): version, capabilities,
 *      limitations, status — so user knows what mrsh can do on this phone.
 *
 * bd: rsh-10qh, rsh-viro (storage perms), rsh-w52b (info page).
 */
public class MainActivity extends Activity {

    private static final int REQ_STORAGE_LEGACY = 1001;
    private static final String TAG = "mrsh.ui";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent svc = new Intent(this, MrshService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }

        requestStoragePermissions();
        setContentView(buildInfoView());
    }

    @Override
    protected void onResume() {
        super.onResume();
        setContentView(buildInfoView());
    }

    private View buildInfoView() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(36, 60, 36, 60);
        scroll.addView(root);

        // Header: app version
        root.addView(header("mrsh-android"));
        root.addView(monoLine("Version: " + appVersion()));
        root.addView(monoLine("libmrsh.so: " + libmrshVersion()));
        root.addView(spacer(20));

        // Identity
        root.addView(header("Identity"));
        root.addView(monoLine("DeviceID: " + deviceId()));
        root.addView(monoLine("Hostname: " + hostname()));
        root.addView(monoLine("Android: " + Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")"));
        root.addView(monoLine("Model: " + Build.MANUFACTURER + " " + Build.MODEL));
        root.addView(spacer(20));

        // Network
        root.addView(header("Network"));
        root.addView(monoLine("Listening: 0.0.0.0:8822 (mrsh server)"));
        root.addView(monoLine("Connectivity: " + connectivity()));
        root.addView(monoLine("WiFi IP: " + wifiIp()));
        root.addView(monoLine("Rendezvous: rendezvous.example.com:21116"));
        root.addView(spacer(20));

        // Permissions / capabilities
        root.addView(header("Storage permissions"));
        boolean allFiles = storageGranted();
        root.addView(statusLine("All-files access", allFiles));
        if (!allFiles && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            root.addView(monoLine("  → Settings → mrsh → Permissions → All files"));
        }
        root.addView(spacer(20));

        // Capabilities — what mrsh CAN do
        root.addView(header("✓ Cosa può fare"));
        root.addView(monoLine("• Esegui comando shell (mrsh -h <ip> exec ...)"));
        root.addView(monoLine("• Push/pull file (anche /sdcard/* se grant ok)"));
        root.addView(monoLine("• Info server (mrsh -h <ip> server-version)"));
        root.addView(monoLine("• Fleet discover (rdv-based group membership)"));
        root.addView(monoLine("• Sopravvive al reboot (BootReceiver)"));
        root.addView(monoLine("• Wake-lock attivo (rimane raggiungibile in doze)"));
        root.addView(spacer(20));

        // Limitations — what mrsh CANNOT do
        root.addView(header("✗ Cosa non può fare"));
        root.addView(monoLine("• Install APK silente (servo tap utente)"));
        root.addView(monoLine("• dumpsys di altre app (perm denied)"));
        root.addView(monoLine("• Input tap/swipe simulati"));
        root.addView(monoLine("• Lettura /data/data/<altra-app>/"));
        root.addView(monoLine("• Force-stop altre app"));
        root.addView(monoLine("Per queste serve Shizuku attivo OR root."));
        root.addView(spacer(20));

        root.addView(header("Status"));
        root.addView(monoLine("Service: running (vedi notifica permanente)"));
        root.addView(monoLine("Puoi chiudere questa pagina, il server"));
        root.addView(monoLine("continua a girare in background."));

        return scroll;
    }

    private TextView header(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        t.setPadding(0, 8, 0, 6);
        return t;
    }

    private TextView monoLine(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setPadding(0, 2, 0, 2);
        return t;
    }

    private View spacer(int dp) {
        TextView t = new TextView(this);
        t.setHeight(dp);
        return t;
    }

    private TextView statusLine(String label, boolean ok) {
        SpannableStringBuilder sb = new SpannableStringBuilder();
        sb.append(label).append(": ");
        String marker = ok ? "✓ granted" : "✗ MISSING";
        int start = sb.length();
        sb.append(marker);
        sb.setSpan(new ForegroundColorSpan(ok ? Color.parseColor("#2E7D32") : Color.parseColor("#C62828")),
                start, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        sb.setSpan(new StyleSpan(Typeface.BOLD), start, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        TextView t = new TextView(this);
        t.setText(sb);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setPadding(0, 2, 0, 2);
        return t;
    }

    // ------- info collectors -------

    private String appVersion() {
        try {
            PackageInfo p = getPackageManager().getPackageInfo(getPackageName(), 0);
            long code = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) ? p.getLongVersionCode() : p.versionCode;
            return p.versionName + " (code " + code + ")";
        } catch (PackageManager.NameNotFoundException e) {
            return "unknown";
        }
    }

    private String libmrshVersion() {
        try {
            File libDir = new File(getApplicationInfo().nativeLibraryDir);
            File lib = new File(libDir, "libmrsh.so");
            if (!lib.exists()) return "(libmrsh.so not found at " + libDir + ")";
            Process p = new ProcessBuilder(lib.getAbsolutePath(), "--version")
                    .redirectErrorStream(true)
                    .start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n++ < 3) {
                if (out.length() > 0) out.append(" ");
                out.append(line);
            }
            p.waitFor();
            String s = out.toString().trim();
            return s.isEmpty() ? "(no output)" : s;
        } catch (Exception e) {
            return "(probe failed: " + e.getClass().getSimpleName() + ")";
        }
    }

    private String deviceId() {
        try {
            String aid = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
            if (aid == null || aid.length() < 8) return "(unavailable)";
            // mrsh server derives DeviceID from ANDROID_ID lower 16 hex chars
            return aid.length() > 16 ? aid.substring(0, 16) : aid;
        } catch (Exception e) {
            return "(error)";
        }
    }

    private String hostname() {
        try {
            String n = Build.HOST;
            return n != null && !n.isEmpty() ? n : "(unset)";
        } catch (Exception e) {
            return "(error)";
        }
    }

    private String connectivity() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return "(no cm)";
            NetworkInfo ni = cm.getActiveNetworkInfo();
            if (ni == null) return "OFFLINE";
            return ni.getTypeName() + " (" + (ni.isConnected() ? "connected" : "disconnected") + ")";
        } catch (Exception e) {
            return "(error)";
        }
    }

    private String wifiIp() {
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface nic : Collections.list(nics)) {
                if (nic.isLoopback() || !nic.isUp()) continue;
                String name = nic.getName();
                if (name == null) continue;
                if (!name.startsWith("wlan") && !name.startsWith("eth")) continue;
                for (java.net.InetAddress a : Collections.list(nic.getInetAddresses())) {
                    if (a.getHostAddress() != null && a.getHostAddress().contains(".")) {
                        return a.getHostAddress() + " (" + name + ")";
                    }
                }
            }
            return "(no IPv4)";
        } catch (Exception e) {
            return "(error)";
        }
    }

    private boolean storageGranted() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        try {
            return checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Exception e) {
            return false;
        }
    }

    private void requestStoragePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Exception e) {
                    try {
                        startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                    } catch (Exception ignored) {}
                }
            }
        } else {
            boolean needsRead = checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED;
            boolean needsWrite = checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED;
            if (needsRead || needsWrite) {
                requestPermissions(new String[]{
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                }, REQ_STORAGE_LEGACY);
            }
        }
    }
}
