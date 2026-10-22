package in.ncu.apkgate;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Base64;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;

/**
 * Lets the APK Gate web code list the apps installed on this phone and read the
 * APK file of one of them, so it can be checked against the ReleaseRegistry.
 * Read-only: it never installs, changes or removes anything.
 */
@CapacitorPlugin(name = "InstalledApps")
public class InstalledAppsPlugin extends Plugin {

    private static final long MAX_BYTES = 80L * 1024 * 1024;

    @PluginMethod
    public void listApps(PluginCall call) {
        PackageManager pm = getContext().getPackageManager();
        List<PackageInfo> pkgs = pm.getInstalledPackages(0);
        JSArray out = new JSArray();
        for (PackageInfo p : pkgs) {
            ApplicationInfo ai = p.applicationInfo;
            if (ai == null) continue;
            boolean system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                    && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
            if (system) continue;
            JSObject o = new JSObject();
            o.put("packageName", p.packageName);
            o.put("label", pm.getApplicationLabel(ai).toString());
            long code = Build.VERSION.SDK_INT >= 28 ? p.getLongVersionCode() : p.versionCode;
            o.put("versionCode", code);
            o.put("versionName", p.versionName);
            o.put("size", new File(ai.sourceDir).length());
            o.put("split", ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0);
            out.put(o);
        }
        JSObject ret = new JSObject();
        ret.put("apps", out);
        call.resolve(ret);
    }

    @PluginMethod
    public void readApk(PluginCall call) {
        String pkg = call.getString("packageName");
        if (pkg == null) { call.reject("packageName is required"); return; }
        try {
            ApplicationInfo ai = getContext().getPackageManager().getApplicationInfo(pkg, 0);
            File f = new File(ai.sourceDir);
            if (f.length() > MAX_BYTES) { call.reject("This APK is larger than 80 MB. Try a smaller app."); return; }
            byte[] data = new byte[(int) f.length()];
            try (FileInputStream in = new FileInputStream(f)) {
                int off = 0, n;
                while (off < data.length && (n = in.read(data, off, data.length - off)) > 0) off += n;
            }
            JSObject ret = new JSObject();
            ret.put("data", Base64.encodeToString(data, Base64.NO_WRAP));
            ret.put("path", f.getName());
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Could not read the APK: " + e.getMessage());
        }
    }
}
