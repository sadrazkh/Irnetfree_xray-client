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

android {
    namespace = "com.irnetfree.vpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.irnetfree.vpn"
        minSdk = 26
        targetSdk = 34
        versionCode = (System.getenv("VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("VERSION_NAME") ?: "0.9.0"
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

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
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
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Xray core (AndroidLibXrayLite). Fetched into app/libs by scripts/fetch-libs.sh.
    // Resolved via the flatDir repo declared in settings.gradle.kts.
    implementation(":libv2ray@aar")
}
