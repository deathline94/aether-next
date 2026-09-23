// The boundary is one component for both frontends and lives in the shared
// package. This file only keeps `./components/ErrorBoundary` resolving, and the
// two apps' copies are identical because they are this file, twice.
export * from "@aether/ui/components/ErrorBoundary";
