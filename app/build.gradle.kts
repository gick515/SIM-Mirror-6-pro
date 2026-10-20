plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.simmirror.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.simmirror.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 60
        versionName = "6.0-Ultra-Pro"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Pure Android SDK & Kotlin Standard Library for zero external dependency conflicts
}
