# Quickstart: Verification Guide for Feature 008

## Prerequisites
- Rust 1.88+ installed
- Node 22+ / npm installed

## Verification Steps

### 1. Connection Tab Banners Verification
1. Launch Desktop app (`npm run dev` in `apps/desktop`) or run tests.
2. In `ConnectionTab`:
   - Force a peer in settings or click a discovered gateway: verify `.pinned-peer-bar` renders as a styled cyan/blue pill with clear spacing between the IP code block and the "Clear (Scan dynamically)" button.
   - Trigger a simulated connection error: verify `.error-banner` renders as a red/coral card with warning icon, padding, and hoverable dismiss button.
3. Verify identical styling on Android.

### 2. Scanner Tab Stepper Sizing & Validation Verification
1. Navigate to the Scanner Tab.
2. Inspect the **Concurrency (Workers)** and **Timeout (ms)** inputs:
   - Verify each input is compactly styled with outer `[ − ]` and `[ + ]` buttons and a centered number display.
   - Verify there is no excessive dead black space to the right, and no vertical divider line artifact.
3. Test typing `240` into the Concurrency input and clicking outside (blur):
   - Verify NO browser tooltip error ("enter a value between 231 to 241") appears.
   - Verify any integer between 1 and 500 can be entered.

### 3. Protocol Category Isolation Verification
1. Select **WireGuard** in Scanner Tab and run a scan to discover WireGuard endpoints.
2. Observe endpoints list and the WireGuard tab count (e.g. 5 endpoints).
3. Switch protocol to **MASQUE H2** and click "Start Scan".
4. Verify:
   - Only the MASQUE H2 category is reset and updated.
   - The 5 WireGuard endpoints remain in the list under the "WireGuard" and "All Protocols" tabs.

### 4. Build & Parity Checks
```bash
# Engine unit tests
cd aether && cargo test

# Desktop build
cd apps/desktop && npm run build

# Android build & sync
cd apps/android && npm run sync-www
```
