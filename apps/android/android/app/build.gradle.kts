plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.aethernext"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.aethernext"
        minSdk = 26
        targetSdk = 34
        versionCode = 102
        versionName = "1.0.2"
    }

    // Per-ABI APKs + one fat universal (all engines inside).
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Sideload-ready: no Play Store keystore in CI yet.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        buildConfig = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.webkit:webkit:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

// Fail the build early if the React UI was not synced into assets/www.
tasks.register("checkWwwAssets") {
    doLast {
        val index = file("src/main/assets/www/index.html")
        check(index.exists()) {
            "Missing assets/www/index.html — run: cd apps/android && npm run sync-www"
        }
    }
}
tasks.named("preBuild").configure { dependsOn("checkWwwAssets") }
