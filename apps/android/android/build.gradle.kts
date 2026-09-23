plugins {
    // AGP 8.11.2 is the first plugin line whose documented maximum API level is 36
    // (AGP 8.9 and earlier stop at 35), which is what `compileSdk = 36` in
    // app/build.gradle.kts asks for: API 36 is the Play minimum for new apps and
    // updates from 2026-08-31, and 16 KB-aligned packaging needs 8.7+. The Gradle
    // wrapper is at AGP's own documented minimum (8.13), so the build no longer
    // warns that the plugin was tested only through SDK 35.
    id("com.android.application") version "8.11.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
