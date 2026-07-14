plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "com.example.combinedtunnel"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
    }
}

dependencies {
    implementation(files("libs/combined-tunnel.aar"))
}
