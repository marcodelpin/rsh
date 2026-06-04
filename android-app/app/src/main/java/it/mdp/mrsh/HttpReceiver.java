package it.mdp.mrsh;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

/**
 * HttpReceiver — HTTP client endpoint via broadcast.
 *
 * Trigger:
 *   am broadcast --user 0 -a it.mdp.mrsh.HTTP \
 *     --es method POST \
 *     --es url 'http://metrics.example.local:8428/api/v1/import/prometheus' \
 *     --es headers '{"Content-Type":"text/plain"}' \
 *     --es body_file /sdcard/Download/metrics.txt \
 *     --es out /sdcard/Download/resp.txt
 *
 * Extras:
 *   method      GET|POST|PUT|DELETE|PATCH (default GET)
 *   url         (required) full URL
 *   headers     optional JSON object {"Key":"Value", ...}
 *   body        inline string body (if no body_file)
 *   body_file   path to file containing body bytes (preferred for large payloads)
 *   out         output path; written as: STATUS\\n\\nHEADERS...\\n\\nBODY (default /sdcard/Download/mrsh-http-resp.txt)
 *   timeout     connect+read timeout in ms (default 10000)
 *
 * No external deps (HttpURLConnection + org.json from Android framework).
 *
 * bd: rsh-crxd (absorb-F).
 */
public class HttpReceiver extends BroadcastReceiver {

    private static final String TAG = "mrsh.http";

    @Override
    public void onReceive(Context context, Intent intent) {
        String method = orDefault(intent.getStringExtra("method"), "GET").toUpperCase();
        String url = intent.getStringExtra("url");
        String headersJson = intent.getStringExtra("headers");
        String body = intent.getStringExtra("body");
        String bodyFile = intent.getStringExtra("body_file");
        String out = orDefault(intent.getStringExtra("out"),
                "/sdcard/Download/mrsh-http-resp.txt");
        int timeout = intent.getIntExtra("timeout", 10000);

        if (url == null || url.isEmpty()) {
            Log.w(TAG, "missing 'url' extra");
            writeError(out, "missing url");
            return;
        }

        Log.i(TAG, "request: " + method + " " + url);

        // Run on background thread — broadcasts dispatch on main thread, network on main = NetworkOnMainThreadException.
        new Thread(() -> performRequest(method, url, headersJson, body, bodyFile, out, timeout),
                "mrsh-http-" + System.currentTimeMillis()).start();
    }

    private void performRequest(String method, String urlStr, String headersJson,
                                 String body, String bodyFile, String outPath, int timeout) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            conn.setInstanceFollowRedirects(true);

            // Headers
            if (headersJson != null && !headersJson.isEmpty()) {
                try {
                    JSONObject h = new JSONObject(headersJson);
                    java.util.Iterator<String> keys = h.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        conn.setRequestProperty(k, h.getString(k));
                    }
                } catch (Exception e) {
                    Log.w(TAG, "bad headers JSON: " + e.getMessage());
                }
            }

            // Body
            boolean hasBody = body != null || bodyFile != null;
            if (hasBody) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    if (bodyFile != null) {
                        try (FileInputStream fis = new FileInputStream(bodyFile)) {
                            byte[] buf = new byte[8192];
                            int n;
                            long total = 0;
                            while ((n = fis.read(buf)) > 0) {
                                os.write(buf, 0, n);
                                total += n;
                            }
                            Log.i(TAG, "body_file streamed " + total + " bytes");
                        }
                    } else {
                        os.write(body.getBytes("UTF-8"));
                    }
                }
            }

            int code = conn.getResponseCode();
            String message = conn.getResponseMessage();
            Map<String, List<String>> headers = conn.getHeaderFields();

            // Response stream — use error stream if status >= 400
            InputStream respStream;
            if (code >= 400) {
                respStream = conn.getErrorStream();
            } else {
                respStream = conn.getInputStream();
            }

            File out = new File(outPath);
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            try (BufferedOutputStream fos = new BufferedOutputStream(new FileOutputStream(out))) {
                String line = "HTTP/1.1 " + code + " " + (message != null ? message : "") + "\n";
                fos.write(line.getBytes("UTF-8"));
                for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                    if (e.getKey() == null) continue; // skip status-line entry
                    for (String v : e.getValue()) {
                        fos.write((e.getKey() + ": " + v + "\n").getBytes("UTF-8"));
                    }
                }
                fos.write("\n".getBytes("UTF-8"));
                if (respStream != null) {
                    byte[] buf = new byte[8192];
                    int n;
                    long total = 0;
                    while ((n = respStream.read(buf)) > 0) {
                        fos.write(buf, 0, n);
                        total += n;
                    }
                    Log.i(TAG, "response: " + code + " body " + total + " bytes -> " + outPath);
                } else {
                    Log.i(TAG, "response: " + code + " (no body) -> " + outPath);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "http failed: " + e.getMessage(), e);
            writeError(outPath, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private void writeError(String outPath, String msg) {
        try {
            File out = new File(outPath);
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(("ERROR: " + msg + "\n").getBytes("UTF-8"));
            }
        } catch (Exception ignored) {}
    }

    private String orDefault(String s, String d) { return (s == null || s.isEmpty()) ? d : s; }
}
