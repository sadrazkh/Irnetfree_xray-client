pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        // AndroidLibXrayLite (libv2ray) is fetched into app/libs by scripts/fetch-libs.sh
        flatDir { dirs("app/libs") }
    }
}

rootProject.name = "IRNetFree"
include(":app")
