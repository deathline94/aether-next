import { Component, type ErrorInfo, type ReactNode } from "react";

/**
 * Has anything the boundary is keyed on actually changed?
 *
 * Extracted and exported because this comparison — not React's error plumbing —
 * is the part that decides whether a crashed tab comes back when the user switches
 * away and returns, or when a settings reload lands. The boundary itself is
 * deliberately untested: under React 19 + jsdom a child that throws during render
 * is rethrown out of `act()` and the tree is unmounted, so the fallback is not
 * observable in a unit test (see specs/015 T186). Proving the recovery path needs a
 * real browser context.
 */
export function resetKeysChanged(
  previous: readonly unknown[] | undefined,
  next: readonly unknown[] | undefined,
): boolean {
  if (previous === undefined || next === undefined) {
    return previous !== next;
  }
  if (previous === next) return false;
  if (previous.length !== next.length) return true;
  return previous.some((value, index) => !Object.is(value, next[index]));
}

interface ErrorBoundaryState {
  error: Error | null;
  resetKeys: readonly unknown[] | undefined;
}

export interface ErrorBoundaryProps {
  children: ReactNode;
  /**
   * Which part of the UI this guards. The fallback names it, because with one
   * boundary per tab "the Scanner tab had a problem" is actionable information and
   * "Something went wrong" is not.
   */
  label?: string;
  /** Any change clears the fallback — the tab re-renders as if retried. */
  resetKeys?: readonly unknown[];
  /**
   * Re-run this view's own recovery rather than re-rendering the same input and
   * crashing again (the Settings tab reloads from disk; the Connection tab would
   * not be asked to re-read settings it is not showing).
   */
  onRetry?: () => void;
}

/**
 * Guard a subtree against a render error.
 *
 * Mounted twice over, deliberately: once at the root in `main.tsx` with no props
 * (the last resort, whose fallback says "Something went wrong"), and once per tab
 * in `App.tsx` with a `label` and `resetKeys` (the recovery path: a fresh session
 * frame, a settings reload, or simply switching tabs and back). A boundary is
 * mounted with its tab, so leaving a crashed tab and returning resets it.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, resetKeys: this.props.resetKeys };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { error };
  }

  static getDerivedStateFromProps(
    props: ErrorBoundaryProps,
    state: ErrorBoundaryState,
  ): Partial<ErrorBoundaryState> | null {
    if (!state.error) {
      // Keep the tracked keys current even while healthy, or the first crash after
      // a tab switch would see a stale list and clear itself immediately.
      return state.resetKeys === props.resetKeys ? null : { resetKeys: props.resetKeys };
    }
    return resetKeysChanged(state.resetKeys, props.resetKeys)
      ? { error: null, resetKeys: props.resetKeys }
      : null;
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled render error:", error, info.componentStack);
  }

  private retry = () => {
    this.setState({ error: null });
    this.props.onRetry?.();
  };

  render() {
    if (this.state.error) {
      return (
        <div className="crash-screen" role="alert">
          <h1>{this.props.label ? `${this.props.label} could not be drawn` : "Something went wrong"}</h1>
          <p>
            This view hit an unexpected error. The tunnel engine is unaffected and the
            other tabs still work.
          </p>
          <code>{this.state.error.message}</code>
          <button type="button" onClick={this.retry}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
