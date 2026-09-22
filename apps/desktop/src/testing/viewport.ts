/**
 * jsdom performs no layout: every element's client rect is 0×0, so a virtualiser
 * measures a viewport of zero height and mounts **no rows at all**. A test that
 * asserts anything about windowed content has to hand the scroll container a size
 * first, or it passes by proving nothing.
 *
 * Patching the prototype (rather than one node) is deliberate: the component
 * keeps its own ref to the panel, and the test cannot reach it before the first
 * render that asks for the viewport.
 */
export function stubViewport(heightPx: number, widthPx = 420): () => void {
  const proto = Element.prototype;
  const previous = proto.getBoundingClientRect;
  proto.getBoundingClientRect = function (this: Element) {
    const real = previous.call(this);
    // Only fake the empty case, so anything jsdom does measure still counts.
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

  // The rect alone is not enough: the virtualiser only re-reads it when the
  // scroll element is *reported* to have resized, and jsdom ships no
  // ResizeObserver at all - so its measurement never happens and the window stays
  // empty. Deliver one entry per observed element, synchronously.
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
