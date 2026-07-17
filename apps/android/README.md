# Android app

```text
cd apps\android
npm install
npm run sync-www
cd android
gradlew assembleDebug
```

Stage `libaether.so` under `app/src/main/jniLibs/<abi>/` for a working tunnel.
