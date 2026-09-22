# Release shrinking rules.
#
# The file used to be a placeholder that stripped nothing, which meant two things:
# every debug log line the app writes (engine output, WebView console messages,
# probe targets) shipped into the release APK, and R8 was free to rename the JNI and
# `@JavascriptInterface` surfaces that the native and JS sides look up *by name*.

# ─── 1. The name-keyed surfaces ─────────────────────────────────────────────────

# hev-socks5-tunnel's JNI binds `TProxyStartService` / `TProxyStopService` /
# `TProxyGetStats` on `app.aethernext.AetherVpnService`. A rename or a removal is not
# a compile error — it is a tunnel that never starts on a device.
-keepclasseswithmembernames,includedescriptorclasses class app.aethernext.AetherVpnService {
    native <methods>;
}

# Same hazard for the WebView bridge: `AetherAndroid.invoke` is called from JavaScript
# by name.
-keepclassmembers,includedescriptorclasses class * {
    @android.webkit.JavascriptInterface <methods>;
}

# The foreground-service and VPN entry points Android instantiates reflectively.
-keep class app.aethernext.AetherVpnService
-keep class app.aethernext.EngineService
-keep class app.aethernext.MainActivity
-keep class app.aethernext.AetherApp
-keep class app.aethernext.BootReceiver

# ─── 2. What must not ship ──────────────────────────────────────────────────────

# Verbose logging is removed at the bytecode level, not merely silenced: it keeps
# `Log.d`/`Log.i` argument construction (string concatenation of endpoints, ports and
# engine output) out of the release DEX as well. `w` and `e` stay — a VPN app that
# cannot say why it failed is a support ticket with no content.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# `System.out` is the same leak through a different door.
-assumenosideeffects class java.io.PrintStream {
    public *** println(...);
    public *** print(...);
}

# Drop the debug-only WebView plumbing from release entirely (BuildConfig.DEBUG is a
# compile-time constant, so R8 removes the branches; keeping it explicit documents that
# the gating is load-bearing, not decorative).
-keepclassmembers class app.aethernext.BuildConfig {
    public static final boolean DEBUG;
    public static final java.lang.String VERSION_NAME;
}

# ─── 3. Standard hygiene ────────────────────────────────────────────────────────

-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
