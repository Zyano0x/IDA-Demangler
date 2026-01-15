# Demangler Plugin for IDA Pro

Multi-language C++ name mangler/demangler plugin with support for MSVC, GCC, Rust, D, and Borland.

## Features

- **Multi-language Support**: Automatically detect and handle different mangling schemes
- **Bidirectional**: Convert between C++ names and mangled names
- **Undo Support**: Revert up to 100 recent rename operations
- **Symbol Browser**: View all mangled symbols in the database
- **Context Menu**: Integrated into right-click menu

## Supported Schemes

| Scheme      | Prefix    | Compiler/Language    |
| ----------- | --------- | -------------------- |
| MSVC        | `?`       | Microsoft Visual C++ |
| Itanium ABI | `_Z`      | GCC, Clang, Intel    |
| Rust v0     | `_R`      | Rust (new)           |
| Rust Legacy | `_ZN...$` | Rust (old)           |
| D Language  | `_D`      | DMD, LDC             |
| Borland     | `@`       | Borland C++          |

## Installation

Copy `demangler.py` to your IDA Pro plugins directory:

```
%IDADIR%/plugins/demangler.py
```

## Usage

### Hotkeys

| Hotkey         | Action                      |
| -------------- | --------------------------- |
| `Shift+N`      | Rename symbol with C++ name |
| `Ctrl+Shift+N` | Show mangling information   |
| `Ctrl+Shift+Z` | Undo last rename            |
| `Ctrl+Alt+N`   | Open Symbol Browser         |

### Rename Symbol (Shift+N)

1. Place cursor at the address to rename
2. Press `Shift+N`
3. Enter name in one of the following formats:
   - **C++ name**: `ClassName::MethodName`
   - **Template**: `ClassName<int>::Method<char>`
   - **Operator**: `MyClass::operator==`
   - **Destructor**: `MyClass::~MyClass`
   - **Mangled name**: `?Method@Class@@QAEXXZ`

### Examples

```
Input                              → Output (MSVC x64)
───────────────────────────────────────────────────────
CString::GetLength                 → ?GetLength@CString@@QEAAXXZ
Vector<int>::push_back             → ?push_back@?$Vector@H@@QEAAXXZ
MyClass::operator==                → ??8MyClass@@QEAAXXZ
MyClass::~MyClass                  → ??1MyClass@@QEAAXXZ
ns::inner::Class::Method           → ?Method@Class@inner@ns@@QEAAXXZ
```

### Symbol Browser (Ctrl+Alt+N)

Opens a window displaying all mangled symbols:

- Address
- Mangling scheme
- Mangled name
- Demangled name

Double-click to jump to address.

## Auto-Detection

The plugin automatically detects:

1. **Scheme from symbol**: Based on prefix (`?`, `_Z`, `_R`, `_D`, `@`)
2. **Compiler from binary**: PE/Windows → MSVC, ELF/Mach-O → GCC/Clang
3. **Architecture**: x86 vs x64 for correct calling convention encoding

## Type Encoding

### MSVC Types

| Type      | Code | Type               | Code |
| --------- | ---- | ------------------ | ---- |
| `void`    | X    | `bool`             | \_N  |
| `char`    | D    | `unsigned char`    | E    |
| `short`   | F    | `unsigned short`   | G    |
| `int`     | H    | `unsigned int`     | I    |
| `long`    | J    | `unsigned long`    | K    |
| `__int64` | \_J  | `unsigned __int64` | \_K  |
| `float`   | M    | `double`           | N    |
| `wchar_t` | \_W  | `char16_t`         | \_S  |

### MSVC Operators

| Operator       | Code | Operator          | Code |
| -------------- | ---- | ----------------- | ---- |
| `operator=`    | ??4  | `operator==`      | ??8  |
| `operator!=`   | ??9  | `operator[]`      | ??A  |
| `operator+`    | ??H  | `operator-`       | ??G  |
| `operator*`    | ??D  | `operator/`       | ??K  |
| `operator new` | ??2  | `operator delete` | ??3  |

## Troubleshooting

### Incorrect mangling

The plugin uses default calling convention (`__thiscall` for member functions). If the function has a different signature, mangling may not match 100%.

**Workaround**: Set function type in IDA before renaming so the plugin can read the signature.

### Cannot demangle

Some complex mangled names (nested templates, RTTI info) may not demangle properly. Try:

1. Use IDA's built-in demangle: View → Open subviews → Local types
2. Check if the symbol is truncated

## Version History

- **v2.0**: Multi-language support, Undo, Symbol Browser, Context Menu
- **v1.0**: Basic MSVC mangling

## License

MIT License

## References

- MSVC mangling: [Wikiversity](https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling)
- Itanium ABI: [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html)
- Rust mangling: [RFC 2603](https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html)
