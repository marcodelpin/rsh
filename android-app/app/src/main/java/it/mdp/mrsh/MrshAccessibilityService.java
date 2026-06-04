package it.mdp.mrsh;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Path;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

/**
 * MrshAccessibilityService — UI automation bridge.
 *
 * Activation: user one-time grant in Settings → Accessibility → mrsh-android.
 * After that, mrsh exec can dispatch broadcasts to this service to:
 *   - tap (x, y)
 *   - swipe (x1, y1) → (x2, y2)
 *   - find on-screen node by text and tap it
 *   - find input field by text and set its content
 *   - silent screenshot (API 30+, no MediaProjection consent)
 *
 * Triggered via internal BroadcastReceiver. The mrsh exec wrapper sends
 * broadcasts via:
 *   am broadcast -a it.mdp.mrsh.A11Y_CMD --es action tap --ei x 540 --ei y 1200
 *
 * bd: rsh-9mzt (absorb-E from rsh-gz0z).
 */
public class MrshAccessibilityService extends AccessibilityService {

    private static final String TAG = "mrsh.a11y";
    public static final String ACTION_CMD = "it.mdp.mrsh.A11Y_CMD";

    private final BroadcastReceiver cmdReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            handleCommand(intent);
        }
    };

    @Override
    public void onServiceConnected() {
        super.onServiceConnected();
        Log.i(TAG, "service connected — accessibility automation ready");
        IntentFilter filter = new IntentFilter(ACTION_CMD);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(cmdReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(cmdReceiver, filter);
        }
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // No-op: we drive ourselves via broadcasts, not by reacting to events.
    }

    @Override
    public void onInterrupt() {
        // No-op.
    }

    @Override
    public void onDestroy() {
        try { unregisterReceiver(cmdReceiver); } catch (Exception ignored) {}
        Log.i(TAG, "service destroyed");
        super.onDestroy();
    }

    /**
     * Dispatch from broadcast intent extras. Logged for debug visibility.
     */
    private void handleCommand(Intent intent) {
        String action = intent.getStringExtra("action");
        if (action == null) {
            Log.w(TAG, "missing 'action' extra");
            return;
        }
        Log.i(TAG, "cmd: " + action);
        try {
            switch (action) {
                case "tap": {
                    int x = intent.getIntExtra("x", -1);
                    int y = intent.getIntExtra("y", -1);
                    if (x < 0 || y < 0) { Log.w(TAG, "tap: bad x/y"); return; }
                    tap(x, y);
                    break;
                }
                case "swipe": {
                    int x1 = intent.getIntExtra("x1", -1);
                    int y1 = intent.getIntExtra("y1", -1);
                    int x2 = intent.getIntExtra("x2", -1);
                    int y2 = intent.getIntExtra("y2", -1);
                    int dur = intent.getIntExtra("dur", 300);
                    if (x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0) { Log.w(TAG, "swipe: bad coords"); return; }
                    swipe(x1, y1, x2, y2, dur);
                    break;
                }
                case "tap_text": {
                    String text = intent.getStringExtra("text");
                    if (text == null || text.isEmpty()) { Log.w(TAG, "tap_text: empty text"); return; }
                    tapByText(text);
                    break;
                }
                case "tap_desc": {
                    String desc = intent.getStringExtra("desc");
                    if (desc == null || desc.isEmpty()) { Log.w(TAG, "tap_desc: empty desc"); return; }
                    tapByContentDescription(desc);
                    break;
                }
                case "set_text": {
                    String text = intent.getStringExtra("text");
                    String matchText = intent.getStringExtra("match"); // optional: text to find input by
                    if (text == null) { Log.w(TAG, "set_text: null text"); return; }
                    setTextInFocusedOrFound(text, matchText);
                    break;
                }
                case "screencap": {
                    String out = intent.getStringExtra("out");
                    if (out == null || out.isEmpty()) {
                        out = "/sdcard/Download/mrsh-a11y-" + System.currentTimeMillis() + ".png";
                    }
                    silentScreencap(out);
                    break;
                }
                case "dump_window": {
                    String out = intent.getStringExtra("out");
                    if (out == null || out.isEmpty()) {
                        out = "/sdcard/Download/mrsh-window.txt";
                    }
                    dumpWindow(out);
                    break;
                }
                default:
                    Log.w(TAG, "unknown action: " + action);
            }
        } catch (Exception e) {
            Log.e(TAG, "handleCommand failed: " + e.getMessage(), e);
        }
    }

    // ---- gesture primitives ----

    private void tap(int x, int y) {
        Path p = new Path();
        p.moveTo(x, y);
        GestureDescription.StrokeDescription stroke =
                new GestureDescription.StrokeDescription(p, 0, 60);
        GestureDescription gesture = new GestureDescription.Builder()
                .addStroke(stroke).build();
        boolean ok = dispatchGesture(gesture, null, null);
        Log.i(TAG, "tap(" + x + "," + y + ") dispatched=" + ok);
    }

    private void swipe(int x1, int y1, int x2, int y2, int durMs) {
        Path p = new Path();
        p.moveTo(x1, y1);
        p.lineTo(x2, y2);
        GestureDescription.StrokeDescription stroke =
                new GestureDescription.StrokeDescription(p, 0, durMs);
        GestureDescription gesture = new GestureDescription.Builder()
                .addStroke(stroke).build();
        boolean ok = dispatchGesture(gesture, null, null);
        Log.i(TAG, "swipe(" + x1 + "," + y1 + " -> " + x2 + "," + y2 + ") dispatched=" + ok);
    }

    // ---- node-based primitives ----

    private void tapByContentDescription(String descNeedle) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) { Log.w(TAG, "tap_desc: null root"); return; }
        AccessibilityNodeInfo match = findByDesc(root, descNeedle);
        if (match == null) {
            Log.w(TAG, "tap_desc: no node matching desc='" + descNeedle + "'");
            return;
        }
        AccessibilityNodeInfo target = match;
        while (target != null && !target.isClickable()) {
            target = target.getParent();
        }
        if (target == null) {
            Log.w(TAG, "tap_desc: no clickable ancestor for desc='" + descNeedle + "'");
            return;
        }
        boolean ok = target.performAction(AccessibilityNodeInfo.ACTION_CLICK);
        Log.i(TAG, "tap_desc: clicked desc='" + descNeedle + "' ok=" + ok);
    }

    private AccessibilityNodeInfo findByDesc(AccessibilityNodeInfo n, String needle) {
        if (n == null) return null;
        CharSequence d = n.getContentDescription();
        if (d != null && d.toString().toLowerCase().contains(needle.toLowerCase())) {
            return n;
        }
        for (int i = 0; i < n.getChildCount(); i++) {
            AccessibilityNodeInfo r = findByDesc(n.getChild(i), needle);
            if (r != null) return r;
        }
        return null;
    }

    private void tapByText(String text) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) { Log.w(TAG, "tap_text: null root"); return; }
        List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByText(text);
        if (nodes == null || nodes.isEmpty()) {
            Log.w(TAG, "tap_text: no node matching " + text);
            return;
        }
        for (AccessibilityNodeInfo n : nodes) {
            if (n.isClickable()) {
                boolean ok = n.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                Log.i(TAG, "tap_text: clicked '" + text + "' ok=" + ok);
                return;
            }
            // Walk up to find clickable parent.
            AccessibilityNodeInfo parent = n.getParent();
            while (parent != null) {
                if (parent.isClickable()) {
                    boolean ok = parent.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                    Log.i(TAG, "tap_text: clicked parent of '" + text + "' ok=" + ok);
                    return;
                }
                parent = parent.getParent();
            }
        }
        Log.w(TAG, "tap_text: no clickable ancestor for '" + text + "'");
    }

    /**
     * Set text on focused input, or if matchText provided, find input field by
     * surrounding text and set its content.
     */
    private void setTextInFocusedOrFound(String text, String matchText) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) { Log.w(TAG, "set_text: null root"); return; }

        AccessibilityNodeInfo target = null;
        if (matchText != null && !matchText.isEmpty()) {
            // Find by hint or surrounding text, then walk to nearest editable.
            List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByText(matchText);
            if (nodes != null) {
                for (AccessibilityNodeInfo n : nodes) {
                    AccessibilityNodeInfo editable = walkToEditable(n);
                    if (editable != null) { target = editable; break; }
                }
            }
        }
        if (target == null) {
            target = findFocusedEditable(root);
        }
        if (target == null) {
            // Last resort: any editable on screen.
            target = findAnyEditable(root);
        }
        if (target == null) {
            Log.w(TAG, "set_text: no editable target found");
            return;
        }
        Bundle args = new Bundle();
        args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text);
        boolean ok = target.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args);
        Log.i(TAG, "set_text: ok=" + ok + " on " + target.getClassName()
                + " (match=" + matchText + ")");
    }

    private AccessibilityNodeInfo walkToEditable(AccessibilityNodeInfo node) {
        if (node == null) return null;
        if (node.isEditable()) return node;
        AccessibilityNodeInfo parent = node.getParent();
        if (parent != null && parent.isEditable()) return parent;
        // Try siblings via parent's children.
        if (parent != null) {
            for (int i = 0; i < parent.getChildCount(); i++) {
                AccessibilityNodeInfo c = parent.getChild(i);
                if (c != null && c.isEditable()) return c;
            }
        }
        return null;
    }

    private AccessibilityNodeInfo findFocusedEditable(AccessibilityNodeInfo root) {
        AccessibilityNodeInfo f = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT);
        if (f != null && f.isEditable()) return f;
        return null;
    }

    private AccessibilityNodeInfo findAnyEditable(AccessibilityNodeInfo root) {
        if (root.isEditable()) return root;
        for (int i = 0; i < root.getChildCount(); i++) {
            AccessibilityNodeInfo c = root.getChild(i);
            if (c == null) continue;
            AccessibilityNodeInfo e = findAnyEditable(c);
            if (e != null) return e;
        }
        return null;
    }

    // ---- screencap (API 30+) ----

    private void silentScreencap(String outPath) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            Log.w(TAG, "screencap: requires Android 11+ (current SDK=" + Build.VERSION.SDK_INT + ")");
            return;
        }
        Handler main = new Handler(Looper.getMainLooper());
        takeScreenshot(android.view.Display.DEFAULT_DISPLAY,
                Runnable::run,
                new TakeScreenshotCallback() {
                    @Override
                    public void onSuccess(android.accessibilityservice.AccessibilityService.ScreenshotResult result) {
                        try {
                            Bitmap bmp = Bitmap.wrapHardwareBuffer(result.getHardwareBuffer(),
                                    result.getColorSpace());
                            if (bmp == null) { Log.e(TAG, "screencap: wrapHardwareBuffer returned null"); return; }
                            File out = new File(outPath);
                            File parent = out.getParentFile();
                            if (parent != null && !parent.exists()) parent.mkdirs();
                            try (BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(out))) {
                                bmp.compress(Bitmap.CompressFormat.PNG, 90, os);
                            }
                            Log.i(TAG, "screencap: " + out.length() + " bytes -> " + outPath);
                        } catch (Exception e) {
                            Log.e(TAG, "screencap onSuccess: " + e.getMessage(), e);
                        } finally {
                            try { result.getHardwareBuffer().close(); } catch (Exception ignored) {}
                        }
                    }
                    @Override
                    public void onFailure(int errorCode) {
                        Log.e(TAG, "screencap onFailure: errorCode=" + errorCode);
                    }
                });
    }

    // ---- diagnostic ----

    private void dumpWindow(String outPath) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) { Log.w(TAG, "dump_window: null root"); return; }
        StringBuilder sb = new StringBuilder();
        dumpNode(root, 0, sb);
        try {
            File out = new File(outPath);
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            java.io.FileWriter w = new java.io.FileWriter(out);
            w.write(sb.toString());
            w.close();
            Log.i(TAG, "dump_window: " + out.length() + " bytes -> " + outPath);
        } catch (Exception e) {
            Log.e(TAG, "dump_window: " + e.getMessage(), e);
        }
    }

    private void dumpNode(AccessibilityNodeInfo n, int depth, StringBuilder sb) {
        if (n == null) return;
        for (int i = 0; i < depth; i++) sb.append("  ");
        sb.append("[").append(n.getClassName()).append("] ");
        CharSequence text = n.getText();
        if (text != null) sb.append("text='").append(text).append("' ");
        CharSequence content = n.getContentDescription();
        if (content != null) sb.append("desc='").append(content).append("' ");
        // Bounds for coordinate-based tap fallback
        android.graphics.Rect r = new android.graphics.Rect();
        n.getBoundsInScreen(r);
        if (r.width() > 0 && r.height() > 0) {
            sb.append("bounds=[").append(r.left).append(",").append(r.top)
                    .append("][").append(r.right).append(",").append(r.bottom).append("] ");
            sb.append("center=(").append(r.centerX()).append(",").append(r.centerY()).append(") ");
        }
        if (n.isEditable()) sb.append("editable ");
        if (n.isClickable()) sb.append("clickable ");
        if (n.isFocused()) sb.append("focused ");
        sb.append("\n");
        for (int i = 0; i < n.getChildCount(); i++) {
            dumpNode(n.getChild(i), depth + 1, sb);
        }
    }
}
