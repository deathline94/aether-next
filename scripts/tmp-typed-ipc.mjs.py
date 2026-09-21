import re, sys

p = 'apps/desktop/src-tauri/src/lib.rs'
s = open(p, encoding='utf-8').read()
if 'pub struct CommandError' in s:
    print('already applied')
    sys.exit(0)

anchor = "use zeroize::Zeroize;\n"
assert s.count(anchor) == 1
decl = anchor + '''
/// Structured shell/IPC error.
///
/// Every shell helper used to return `Result<_, String>`, so a caller could only
/// branch on prose (`msg.contains("not found")`) and the frontend received an
/// opaque rejection it had to stringify. `code` is the machine-readable half.
///
/// It serialises as the message string on purpose: the shipped frontend still
/// does `String(e)`, so the wire shape stays compatible until typed
/// (`tauri-specta`) bindings replace those calls in spec 016.
#[derive(Debug, Clone)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl Serialize for CommandError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.message)
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self { code: "internal", message }
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self { code: "internal", message: message.to_string() }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::AlreadyExists => "already_exists",
            _ => "io",
        };
        Self { code, message: e.to_string() }
    }
}
'''
s = s.replace(anchor, decl, 1)

s = re.sub(
    r"Result<([^\n<>]*(?:<[^<>\n]*>)?[^\n<>]*?),\s*String>",
    r"Result<\1, CommandError>",
    s,
)

BS = chr(92)
DQ = chr(34)
out = []
i = 0
n = 0
key = 'Err('
while True:
    j = s.find(key, i)
    if j == -1:
        out.append(s[i:])
        break
    if j > 0 and (s[j - 1].isalnum() or s[j - 1] == '_'):
        out.append(s[i:j + len(key)])
        i = j + len(key)
        continue
    k = j + len(key)
    depth = 1
    while k < len(s) and depth > 0:
        c = s[k]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                break
        elif c == DQ:
            k += 1
            while k < len(s) and s[k] != DQ:
                if s[k] == BS:
                    k += 1
                k += 1
        k += 1
    if depth != 0:
        out.append(s[i:j + len(key)])
        i = j + len(key)
        continue
    inner = s[j + len(key):k]
    if inner.strip() == '':
        out.append(s[i:j + len(key)])
        i = j + len(key)
        continue
    out.append(s[i:j + len(key)])
    out.append(inner)
    out.append('.into())')
    n += 1
    i = k + 1
s = ''.join(out)
print('Err() sites wrapped:', n)
open(p, 'w', encoding='utf-8').write(s)
