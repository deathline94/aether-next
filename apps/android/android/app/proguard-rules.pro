# Keep bridge entry points (must match package app.aethernext)
-keepclassmembers class app.aethernext.AetherBridge {
    @android.webkit.JavascriptInterface <methods>;
}
