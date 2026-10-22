# Native methods are resolved by class name, and onNativeShareFound is
# looked up with GetMethodID. Keep both if R8 minify is enabled for release.
-keep class com.xtefoundation.cryptonoteminer.ChukwaHasher {
    public void onNativeShareFound(java.lang.String, int, byte[]);
    native <methods>;
}
