# Keep the Xray core (libv2ray) + gomobile bindings intact.
-keep class libv2ray.** { *; }
-keep class go.** { *; }
-keep class com.irnetfree.vpn.vpn.** { *; }
-dontwarn libv2ray.**
-dontwarn go.**
