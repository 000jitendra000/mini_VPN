plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.tinyvpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.tinyvpn"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        
        externalNativeBuild {
            cmake {
                // Ensure CMake builds our Rust code if needed, but since we compile it via cargo,
                // we'll just pull the generated .so files via jniLibs! 
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
}
