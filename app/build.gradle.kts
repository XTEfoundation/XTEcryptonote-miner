plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

import java.util.Properties
import java.io.FileInputStream

fun loadSigningEnv(): Map<String, String> {
    val map = mutableMapOf<String, String>()
    // Prefer environment variables
    listOf("KEYSTORE_PATH", "KEY_ALIAS", "STORE_PASSWORD", "KEY_PASSWORD").forEach { k ->
        System.getenv(k)?.let { map[k] = it }
    }
    // Optional secrets env file outside the repo
    val envFile = file("/workspace/secrets/xte-keystore.env")
    if (envFile.exists()) {
        envFile.readLines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) return@forEach
            val (k, v) = t.split("=", limit = 2)
            map.putIfAbsent(k.trim(), v.trim())
        }
    }
    // Optional local keystore.properties (gitignored)
    val propsFile = rootProject.file("keystore.properties")
    if (propsFile.exists()) {
        val p = Properties()
        FileInputStream(propsFile).use { p.load(it) }
        p.getProperty("storeFile")?.let { map.putIfAbsent("KEYSTORE_PATH", it) }
        p.getProperty("keyAlias")?.let { map.putIfAbsent("KEY_ALIAS", it) }
        p.getProperty("storePassword")?.let { map.putIfAbsent("STORE_PASSWORD", it) }
        p.getProperty("keyPassword")?.let { map.putIfAbsent("KEY_PASSWORD", it) }
    }
    return map
}

val signingEnv = loadSigningEnv()
val hasReleaseKey = signingEnv["KEYSTORE_PATH"]?.let { file(it).exists() } == true
        && !signingEnv["KEY_ALIAS"].isNullOrBlank()
        && !signingEnv["STORE_PASSWORD"].isNullOrBlank()
        && !signingEnv["KEY_PASSWORD"].isNullOrBlank()

android {
    namespace = "com.xtefoundation.cryptonoteminer"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.xtefoundation.cryptonoteminer"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-O3", "-fexceptions", "-frtti")
                arguments += listOf("-DANDROID_STL=c++_shared")
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = file(signingEnv.getValue("KEYSTORE_PATH"))
                storePassword = signingEnv.getValue("STORE_PASSWORD")
                keyAlias = signingEnv.getValue("KEY_ALIAS")
                keyPassword = signingEnv.getValue("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseKey) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
}
