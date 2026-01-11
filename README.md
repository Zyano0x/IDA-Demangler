# Demangler

IDA Pro plugin for working with MSVC C++ mangled names.

## Install

Drop into your IDA plugins folder:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- Linux/Mac: `~/.idapro/plugins/`

## Usage

Press `Shift+N` at any address.

**Input options:**

- Mangled name (starts with `?`) → applies directly, shows demangled in comment
- C++ name like `ClassName::Method` → generates mangled name automatically

**Template classes work too:**

```
ZXString<char>::operator=
CInPacket<int>::Decode
```

## Reference

For operator codes and type encodings, see [Visual C++ name mangling](https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling).

## Examples

```
ZXString<char>::operator=
  → ??4?$ZXString@D@@QAEAAV0@ABV0@@Z     (x86)
  → ??4?$ZXString@D@@QEAAAEAV0@AEBV0@@Z  (x64)

CWvsContext::SendPacket
  → ?SendPacket@CWvsContext@@QAEXXZ     (x86)
  → ?SendPacket@CWvsContext@@QEAAXXZ    (x64)
```

## Notes

- Generates signatures for `__thiscall` member functions
- x86 vs x64 handled automatically based on current IDB
- Falls back to simplified name (`Class_Method`) if renaming fails
