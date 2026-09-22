/**
 * jsdom performs no layout and ships no ResizeObserver, so a windowed list
 * measures a 0-height viewport and mounts nothing: an assertion about "the rows
 * in the panel" would pass against an empty DOM. Give the scroll element a rect
 * and report the resize, synchronously, so the virtualiser actually windows.
 *
 * The desktop app has the same helper (`apps/desktop/src/testing/viewport.ts`);
 * the two test trees cannot import each other's, so this is a deliberate copy of
 * test plumbing rather than a shared module - `packages/ui` is the shipped
 * surface and does not carry stubs.
 */
export function stubViewport(heightPx: number, widthPx = 420): () => void {
  const proto = Element.prototype;
  const previous = proto.getBoundingClientRect;
  proto.getBoundingClientRect = function (this: Element) {
    const real = previous.call(this);
    if (real.height > 0 || real.width > 0) return real;
    return {
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: widthPx,
      bottom: heightPx,
      width: widthPx,
      height: heightPx,
      toJSON: () => ({}),
    } as DOMRect;
  };

  const previousObserver = (globalThis as Record<string, unknown>).ResizeObserver;
  class StubResizeObserver {
    private readonly callback: ResizeObserverCallback;
    constructor(callback: ResizeObserverCallback) {
      this.callback = callback;
    }
    observe = (target: Element) => {
      const rect = target.getBoundingClientRect();
      const entry = {
        target,
        contentRect: { width: rect.width, height: rect.height },
        borderBoxSize: [{ blockSize: rect.height, inlineSize: rect.width }],
        contentBoxSize: [{ blockSize: rect.height, inlineSize: rect.width }],
        devicePixelContentBoxSize: [],
      } as unknown as ResizeObserverEntry;
      this.callback([entry], this as unknown as ResizeObserver);
    };
    unobserve = () => {};
    disconnect = () => {};
  }
  (globalThis as Record<string, unknown>).ResizeObserver = StubResizeObserver;

  return () => {
    proto.getBoundingClientRect = previous;
    (globalThis as Record<string, unknown>).ResizeObserver = previousObserver;
  };
}
