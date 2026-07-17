# Keep bridge entry points
-keepclassmembers class studio.cluvex.aether.AetherBridge {
    @android.webkit.JavascriptInterface <methods>;
}
