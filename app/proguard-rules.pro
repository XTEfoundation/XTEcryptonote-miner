# Native methods are resolved by class name, and onNativeShareFound is
# looked up with GetMethodID. Keep both if R8 minify is enabled for release.
-keep class com.xtefoundation.cryptonoteminer.ChukwaHasher {
    public void onNativeShareFound(java.lang.String, int, byte[]);
    native <methods>;
}

# EdDSA-Java: only the math classes are used. Its JCA provider code references
# sun.security.* classes that do not exist on Android.
-dontwarn sun.security.**
-dontwarn net.i2p.crypto.eddsa.**
-keep class net.i2p.crypto.eddsa.math.** { *; }
-keep class net.i2p.crypto.eddsa.spec.** { *; }
