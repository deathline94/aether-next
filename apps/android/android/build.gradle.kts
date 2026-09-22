plugins {
    // API 36 is the Play minimum for new apps and updates from 2026-08-31, and
    // AGP only knows how to emit 16 KB-aligned, v34+ packaged APKs from 8.7 on.
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
