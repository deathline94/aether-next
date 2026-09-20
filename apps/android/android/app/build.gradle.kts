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
        versionCode = 51
        versionName = "1.2.9"
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
    signingConfigs {
        create("release") {
            val keystore = System.getenv("AETHER_ANDROID_KEYSTORE")
            if (keystore != null) {
                storeFile = file(keystore)
                storePassword = System.getenv("AETHER_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("AETHER_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("AETHER_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
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
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.webkit:webkit:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.json:json:20240303")
}

// Fail the build early if the React UI was not synced into assets/www.
// Skips gracefully when the Gradle invocation targets only tests (no assemble/bundle).
tasks.register("checkWwwAssets") {
    doLast {
        val index = file("src/main/assets/www/index.html")
        val requestedNames = gradle.startParameter.taskNames.map { it.substringAfterLast(':') }
        val isAppBuild = requestedNames.any { it.startsWith("assemble") || it.startsWith("bundle") || it.startsWith("install") }
        if (!index.exists()) {
            if (isAppBuild) {
                throw GradleException("Missing assets/www/index.html — run: cd apps/android && npm run sync-www")
            } else {
                logger.warn("checkWwwAssets: assets/www/index.html absent (OK for unit tests)")
            }
        }
    }
}

tasks.register("checkReleasePayloads") {
    doLast {
        val requiredAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        val requiredLibraries = listOf("libaether.so", "libhev-socks5-tunnel.so")
        requiredAbis.forEach { abi ->
            requiredLibraries.forEach { library ->
                check(file("src/main/jniLibs/$abi/$library").length() > 0) {
                    "Missing $abi/$library - build and stage every advertised ABI"
                }
            }
        }
        val signingInputs = listOf(
            "AETHER_ANDROID_KEYSTORE",
            "AETHER_ANDROID_KEYSTORE_PASSWORD",
            "AETHER_ANDROID_KEY_ALIAS",
            "AETHER_ANDROID_KEY_PASSWORD",
        )
        check(signingInputs.none { System.getenv(it).isNullOrBlank() }) {
            "Release signing missing: set ${signingInputs.joinToString()}"
        }
        check(file(System.getenv("AETHER_ANDROID_KEYSTORE")!!).isFile) {
            "Release keystore file is missing"
        }
    }
}

// AGP creates pre*Build tasks after project evaluation — never call named() at top level.
afterEvaluate {
    tasks.named("preBuild").configure {
        dependsOn("checkWwwAssets")
    }
    // Cover base release + any ABI-split pre*ReleaseBuild variants.
    tasks.matching { it.name.startsWith("pre") && it.name.contains("Release") && it.name.endsWith("Build") }
        .configureEach {
            dependsOn("checkWwwAssets", "checkReleasePayloads")
        }
}
