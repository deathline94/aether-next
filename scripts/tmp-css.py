"""One-shot CSS remediation for both frontend forks (spec 015 US6 / BC-11)."""
import re
import sys

FILES = ['apps/desktop/src/App.css', 'apps/android/src/App.css']

EDGE_TOKENS = """  /* Opaque edge tokens (WCAG 1.4.11). Raw alpha hairlines antialias away at
     Windows 125%/150% scaling and vanish on any surface but the exact one they
     were blended against, so boundaries are composited colours instead. */
  --edge: #232b34;              /* decorative separation, >=1.6:1 vs --panel */
  --edge-interactive: #4a5764;  /* control boundary, >=3:1 vs --panel */
  --edge-strong: #6b7b8a;

  /* Micro-Borders & Architectural Highlights */
"""


def viewport(css):
    css = re.sub(r'min-height:\s*100vh\b', 'min-height: 100svh', css)
    css = re.sub(r'(?<!min-)height:\s*100vh\b', 'height: 100dvh', css)
    css = re.sub(r'calc\(\s*100vh\b', 'calc(100dvh', css)
    return css


def transitions(css):
    props = ('color', 'background-color', 'border-color', 'box-shadow', 'transform', 'opacity')

    def sub(m):
        tail = m.group(1).strip()
        return 'transition: ' + ', '.join(f'{p} {tail}' for p in props) + ';'

    return re.sub(r'transition:\s*all\b([^;]*);', sub, css)


def hairlines(css):
    def sub(m):
        token = '--edge' if float(m.group(1)) < 0.1 else '--edge-interactive'
        return f'border: 1px solid var({token})'

    css = re.sub(r'border:\s*1px solid rgba\(255,\s*255,\s*255,\s*([\d.]+)\)', sub, css)
    css = css.replace('--border-subtle: rgba(255, 255, 255, 0.05);', '--border-subtle: var(--edge);')
    css = css.replace('--border-card: rgba(255, 255, 255, 0.07);', '--border-card: var(--edge);')
    css = css.replace('--border-strong: rgba(255, 255, 255, 0.12);', '--border-strong: var(--edge-interactive);')
    css = css.replace('--line: rgba(255, 255, 255, 0.07);', '--line: var(--edge);')
    css = css.replace('/* Micro-Borders & Architectural Highlights */\n', EDGE_TOKENS, 1)
    return css


def skip_blobs(text, i):
    if text.startswith('/*', i):
        j = text.find('*/', i + 2)
        return len(text) if j == -1 else j + 2
    if text[i] in '"\'':
        q = text[i]
        j = i + 1
        while j < len(text):
            if text[j] == '\\':
                j += 2
                continue
            if text[j] == q:
                return j + 1
            j += 1
        return len(text)
    return i + 1


def match_brace(text, open_idx):
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        if text.startswith('/*', i) or text[i] in '"\'':
            i = skip_blobs(text, i)
            continue
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def needs_wrap(prelude):
    return ':hover' in re.sub(r'(?::not|-moz-any|-webkit-any)\([^()]*\)', '', prelude)


def hover_gated(css):
    """Wrap every hover-dependent rule in a pointer guard, in place."""

    def process(text):
        out = []
        i = 0
        start = 0
        n = len(text)
        while i < n:
            c = text[i]
            if text.startswith('/*', i) or c in '"\'':
                i = skip_blobs(text, i)
                continue
            if c == '{':
                prelude = text[start:i]
                close = match_brace(text, i)
                if close == -1:
                    out.append(text[start:])
                    return ''.join(out)
                body = text[i + 1:close]
                head = prelude.lstrip()
                if head.startswith('@'):
                    name = head.split(None, 1)[0].lower()
                    inner = process(body) if name in ('@media', '@supports') else body
                    out.append(prelude + '{' + inner + '}')
                elif needs_wrap(prelude):
                    out.append('@media (hover: hover){' + prelude + '{' + body + '}}')
                else:
                    out.append(prelude + '{' + body + '}')
                i = start = close + 1
                continue
            if c == '}':
                out.append(text[start:i + 1])
                i = start = i + 1
                continue
            i += 1
        out.append(text[start:])
        return ''.join(out)

    wrapped = process(css)
    # Every original declaration must survive, and the only structural addition
    # may be the pointer guards (balanced braces).
    strip = lambda t: re.findall(r'[-\w]+\s*:\s*[^;{}]+[;}]', t)
    assert len(strip(wrapped)) >= len(strip(css)), 'declarations lost'
    assert wrapped.count('{') == wrapped.count('}')
    return wrapped, css.count('{') , wrapped.count('{')


for path in FILES:
    src = open(path, encoding='utf-8').read()
    before = dict(
        vh100=len(re.findall(r'\b100vh\b', src)),
        trans=len(re.findall(r'transition:\s*all\b', src)),
        hair=len(re.findall(r'border:\s*1px solid rgba\(255,\s*255,\s*255,\s*0?\.\d+\)', src)),
        hover=len(re.findall(r':hover\b', src)),
    )
    out = viewport(src)
    out = transitions(out)
    out = hairlines(out)
    out, braces_before, braces_after = hover_gated(out)
    open(path, 'w', encoding='utf-8').write(out)
    print(path, before, '-> braces', braces_before, braces_after)
