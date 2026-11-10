import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing is driven by env vars (set by CI from GitHub secrets) or a
// local keystore.properties. When absent, `assembleRelease` falls back to the
// debug signing config so CI can still produce an installable APK.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) load(FileInputStream(keystorePropsFile))
}
fun signingValue(propKey: String, envKey: String): String? =
    (keystoreProps.getProperty(propKey) ?: System.getenv(envKey))?.takeIf { it.isNotBlank() }

val ksStorePath = signingValue("storeFile", "ANDROID_KEYSTORE_FILE")
val ksStorePassword = signingValue("storePassword", "ANDROID_KEYSTORE_PASSWORD")
val ksKeyAlias = signingValue("keyAlias", "ANDROID_KEY_ALIAS")
val ksKeyPassword = signingValue("keyPassword", "ANDROID_KEY_PASSWORD")
val hasReleaseSigning = ksStorePath != null && ksStorePassword != null && ksKeyAlias != null && ksKeyPassword != null

// The version: the release workflow's VERSION_NAME (the tag without its "v"), else this default.
val appVersionName = System.getenv("VERSION_NAME")?.takeIf { it.isNotBlank() } ?: "1.47.3"

// versionCode is made of the version itself (1.47.3 -> 1047003), never of a counter.
// Android refuses an APK whose versionCode is lower than the installed one, and all the phone
// says is "App not installed as package appears to be invalid". Until v1.47.2 the code was the
// release workflow's run number: the repository was recreated on 2026-11-08, the number began
// again at 1, and v1.47.1 and v1.47.2 went out as 11 and 12 to phones that held up to 155.
// A counter also gives an old tag that is built again a higher code than a newer version.
// scripts/check-version-code.sh reads the built APK against this rule in both workflows.
fun versionCodeOf(name: String): Int {
    val m = Regex("""^(\d+)\.(\d+)\.(\d+)""").find(name)
        ?: throw GradleException("versionName \"$name\" does not begin with x.y.z: no versionCode can be made of it")
    val major = m.groupValues[1].toInt()
    val minor = m.groupValues[2].toInt()
    val patch = m.groupValues[3].toInt()
    if (minor > 999 || patch > 999) throw GradleException("versionName \"$name\": the second and third numbers must stay under 1000")
    return major * 1_000_000 + minor * 1_000 + patch
}

android {
    namespace = "com.irnetfree.vpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.irnetfree.vpn"
        minSdk = 26
        targetSdk = 34
        versionCode = versionCodeOf(appVersionName)
        versionName = appVersionName
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    if (hasReleaseSigning) {
        signingConfigs {
            create("release") {
                storeFile = file(ksStorePath!!)
                storePassword = ksStorePassword
                keyAlias = ksKeyAlias
                keyPassword = ksKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // signed with the real key when secrets are present, else the debug key
            signingConfig = if (hasReleaseSigning) signingConfigs.getByName("release")
                            else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }

    // Never let lint fail the release assembly (lintVitalRelease) — we want CI to
    // always produce an installable APK.
    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }

    // JVM unit tests: a stray android.* call returns a default instead of
    // throwing "not mocked", so the pure core can be tested off a device.
    testOptions { unitTests.isReturnDefaultValues = true }

    // Ask for the routing data files in assets/ to be stored as they are. The
    // v1.8.0 release APK shows the packager deflated them anyway (+20 MB for
    // 28 MB of data), so nothing depends on this: XrayCore.prepareAssets copies
    // them by stream and re-copies on a new build, not on a size comparison.
    androidResources { noCompress.add("dat") }

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
        // The sing-box CLI ships as libsingbox.so in jniLibs; it must be extracted
        // to the (executable) nativeLibraryDir at install so it can be exec'd —
        // legacy packaging sets extractNativeLibs=true and stores libs uncompressed.
        jniLibs { useLegacyPackaging = true }
    }
    // libv2ray.aar lives in app/libs (fetched by scripts/fetch-libs.sh)
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    // StateFlow used by VpnState — make sure coroutines is on the compile classpath.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // QR code scanning (camera) — self-contained scanner activity + permission.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // HTTP client for subscription fetching.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // TLS 1.3 on every Android version. The platform TLS only has it from
    // Android 10, and the owner's panel sits behind a Cloudflare zone whose
    // minimum TLS version is 1.3 — on Android 8/9 every fetch of it failed with
    // "Handshake failed" (see IRApp.installTls13). Installed as the first
    // security provider it serves OkHttp, HttpURLConnection and raw SSLSocket.
    implementation("org.conscrypt:conscrypt-android:2.7.0")

    // JVM unit tests for the pure core (DnsPlan, ConfigBuilder, LinkParser…): the
    // android.jar on the test classpath stubs org.json, so the real one is added.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")

    // Xray core (AndroidLibXrayLite). Fetched into app/libs by scripts/fetch-libs.sh.
    // Added ONLY when present so the app still builds an installable APK if the
    // fetch was skipped; the core is called via reflection (XrayCore.kt), so the
    // exact upstream API version can't break compilation.
    val libv2ray = file("libs/libv2ray.aar")
    if (libv2ray.exists()) implementation(files(libv2ray))
}
