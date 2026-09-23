// The controls are one file for both frontends and live in the shared package.
// This file only keeps `./ui` / `../components/ui` resolving, and the two apps'
// copies are identical because they are this file, twice.
export * from "@aether/ui/components/ui";
