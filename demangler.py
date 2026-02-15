import ida_kernwin
import ida_name
import ida_frame
import ida_typeinf
import idaapi
import idautils
import idc
import re
import os
from collections import deque
from enum import Enum, auto
from functools import lru_cache
from typing import NamedTuple

PLUGIN_VERSION = "3.0"
MAX_UNDO_HISTORY = 200


class ActionID:
    RENAME = "dem:rename"
    INFO = "dem:info"
    UNDO = "dem:undo"
    BROWSE = "dem:browse"
    BATCH = "dem:batch"
    STATS = "dem:stats"
    ALL = [RENAME, INFO, UNDO, BROWSE, BATCH, STATS]


class Hotkey:
    RENAME = "Shift+N"
    INFO = "Ctrl+Shift+N"
    UNDO = "Ctrl+Shift+Z"
    BROWSE = "Ctrl+Alt+N"
    BATCH = "Ctrl+Shift+D"
    STATS = "Ctrl+Alt+S"


class Scheme(Enum):
    UNKNOWN = auto()
    MSVC = auto()
    ITANIUM = auto()
    RUST_V0 = auto()
    RUST_LEGACY = auto()
    DLANG = auto()
    BORLAND = auto()


SCHEME_NAMES = {
    Scheme.UNKNOWN: "Unknown",
    Scheme.MSVC: "MSVC",
    Scheme.ITANIUM: "GCC/Clang",
    Scheme.RUST_V0: "Rust v0",
    Scheme.RUST_LEGACY: "Rust Legacy",
    Scheme.DLANG: "D",
    Scheme.BORLAND: "Borland",
}

MSVC_OPS = {
    "operator=": "??4", "operator==": "??8", "operator!=": "??9",
    "operator[]": "??A", "operator->": "??C", "operator*": "??D",
    "operator++": "??E", "operator--": "??F", "operator-": "??G",
    "operator+": "??H", "operator&": "??I", "operator/": "??K",
    "operator%": "??L", "operator<": "??M", "operator<=": "??N",
    "operator>": "??O", "operator>=": "??P", "operator()": "??R",
    "operator~": "??S", "operator^": "??T", "operator|": "??U",
    "operator<<": "??6", "operator>>": "??5", "operator!": "??7",
    "operator+=": "??Y", "operator-=": "??Z", "operator*=": "??X",
    "operator new": "??2", "operator delete": "??3",
    "operator new[]": "??_U", "operator delete[]": "??_V",
}

MSVC_TYPES = {
    "char": "D", "signed char": "C", "unsigned char": "E",
    "short": "F", "unsigned short": "G", "int": "H", "unsigned int": "I",
    "long": "J", "unsigned long": "K", "float": "M", "double": "N",
    "long double": "O", "bool": "_N", "void": "X", "wchar_t": "_W",
    "__int64": "_J", "unsigned __int64": "_K",
    "long long": "_J", "unsigned long long": "_K",
    "char16_t": "_S", "char32_t": "_U",
    "BYTE": "E", "WORD": "G", "DWORD": "K", "QWORD": "_K",
    "BOOL": "H", "INT": "H", "UINT": "I", "LONG": "J", "ULONG": "K",
}

ITANIUM_TYPES = {
    "void": "v", "bool": "b", "char": "c", "wchar_t": "w",
    "signed char": "a", "unsigned char": "h",
    "short": "s", "unsigned short": "t", "int": "i", "unsigned int": "j",
    "long": "l", "unsigned long": "m",
    "long long": "x", "unsigned long long": "y",
    "float": "f", "double": "d", "long double": "e",
    "__int64": "x", "unsigned __int64": "y",
}

ITANIUM_OPS = {
    "operator new": "nw", "operator delete": "dl", "operator~": "co",
    "operator+": "pl", "operator-": "mi", "operator*": "ml",
    "operator/": "dv", "operator%": "rm", "operator&": "an",
    "operator|": "or", "operator^": "eo", "operator=": "aS",
    "operator+=": "pL", "operator-=": "mI",
    "operator==": "eq", "operator!=": "ne",
    "operator<": "lt", "operator>": "gt",
    "operator<=": "le", "operator>=": "ge",
    "operator<<": "ls", "operator>>": "rs",
    "operator++": "pp", "operator--": "mm",
    "operator()": "cl", "operator[]": "ix",
}

_RE_RUST_HASH = re.compile(r"17h[0-9a-f]{16}E")
_RE_FUNC_PARAMS = re.compile(r"\(([^)]*)\)")
_RE_MULTI_UNDERSCORE = re.compile(r"_{2,}")
_RE_MSVC_FULL = re.compile(
    r"^((?:[\w]+::)*[\w]+)(?:<([^<>]+)>)?::([\w~]+|operator\S+?)(?:<([^<>]+)>)?$"
)
_RE_MSVC_SIMPLE = re.compile(r"^([\w]+)::([\w~]+|operator\S+)$")
_RE_ITANIUM = re.compile(r"^((?:[\w]+::)*[\w]+)::([\w~]+|operator\S+?)$")

_SANITIZE_TABLE = str.maketrans({
    ":": "_", "<": "_", ">": "_", " ": "_",
    "*": "p", "&": "r", ",": "_", "(": "_", ")": "_",
})


class RenameRecord(NamedTuple):
    ea: int
    old_name: str
    new_name: str


class UndoManager:
    def __init__(self, max_size: int = MAX_UNDO_HISTORY) -> None:
        self._history: deque[RenameRecord] = deque(maxlen=max_size)

    def record(self, ea: int, old_name: str, new_name: str) -> None:
        self._history.append(RenameRecord(ea, old_name, new_name))

    def undo(self) -> RenameRecord | None:
        if not self._history:
            return None
        rec = self._history.pop()
        flags = ida_name.SN_NOWARN | ida_name.SN_FORCE
        if ida_name.set_name(rec.ea, rec.old_name, flags):
            idc.set_cmt(rec.ea, "", 0)
            return rec
        return None

    def can_undo(self) -> bool:
        return len(self._history) > 0

    @property
    def count(self) -> int:
        return len(self._history)

    def export_log(self, filepath: str) -> int:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Demangler Rename Log\n")
            f.write(f"# Records: {len(self._history)}\n")
            f.write("#" + "-" * 78 + "\n")
            f.write(f"{'Address':<18} {'Old Name':<40} {'New Name'}\n")
            f.write("-" * 100 + "\n")
            for rec in self._history:
                f.write(f"{hex(rec.ea):<18} {rec.old_name:<40} {rec.new_name}\n")
        return len(self._history)


def detect_scheme(name: str) -> Scheme:
    if not name or len(name) < 2:
        return Scheme.UNKNOWN
    if name.startswith("?"):
        return Scheme.MSVC
    if name.startswith("_R") and len(name) > 2:
        return Scheme.RUST_V0
    if name.startswith("_Z"):
        if "$" in name or _RE_RUST_HASH.search(name):
            return Scheme.RUST_LEGACY
        return Scheme.ITANIUM
    if name.startswith("_D") and len(name) > 2 and name[2].isdigit():
        return Scheme.DLANG
    if name.startswith("@"):
        return Scheme.BORLAND
    return Scheme.UNKNOWN


@lru_cache(maxsize=1)
def detect_compiler() -> Scheme:
    file_type = idaapi.get_file_type_name()
    if "PE" in file_type or "Windows" in file_type:
        return Scheme.MSVC
    if "ELF" in file_type or "Mach-O" in file_type:
        return Scheme.ITANIUM
    return Scheme.UNKNOWN


def demangle(name: str) -> str | None:
    if not name:
        return None
    try:
        result = idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))
        if result:
            return result
        return idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    except Exception as e:
        print(f"[Demangler] demangle error for '{name}': {e}")
        return None


def sanitize(name: str) -> str:
    if not name:
        return "unnamed"
    name = name.translate(_SANITIZE_TABLE)
    name = _RE_MULTI_UNDERSCORE.sub("_", name)
    return name.strip("_") or "unnamed"


def guess_func_type(ea: int) -> str | None:
    ftype = idc.get_type(ea)
    if ftype and "(" in ftype:
        return ftype

    ftype = idc.guess_type(ea)
    if ftype and "(" in ftype:
        return ftype

    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(ea)
            if cfunc and cfunc.type:
                return str(cfunc.type)
    except (ImportError, Exception):
        pass

    return _guess_from_frame(ea)


def _guess_from_frame(ea: int) -> str | None:
    frame = ida_frame.get_frame(ea)
    if not frame:
        return None

    is_64 = idaapi.inf_is_64bit()
    ptr_size = 8 if is_64 else 4
    arg_types = []

    for i in range(frame.memqty):
        member = frame.get_member(i)
        if member is None:
            continue
        mname = ida_frame.get_member_name(member.id)
        if not mname:
            continue
        if mname.startswith("arg_") or (not is_64 and member.soff > 0):
            msize = member.eoff - member.soff
            if msize <= 4:
                arg_types.append("int")
            else:
                arg_types.append("__int64")

    if not arg_types:
        func = idaapi.get_func(ea)
        if func and is_64:
            return "void __fastcall()"
        return None

    params = ", ".join(arg_types)
    cc = "__fastcall" if is_64 else "__cdecl"
    return f"void {cc}({params})"


def _extract_params(ftype: str) -> list[str]:
    m = _RE_FUNC_PARAMS.search(ftype)
    if not m:
        return []
    params_str = m.group(1).strip()
    if not params_str or params_str.lower() == "void":
        return []
    return [p.strip() for p in params_str.split(",") if p.strip()]


class MSVCMangler:
    def __init__(self) -> None:
        self.x64: bool = idaapi.inf_is_64bit()

    def mangle(self, name: str, ea: int = 0) -> str | None:
        if not name:
            return None

        if "::" not in name:
            return self._mangle_free(name, ea)

        m = _RE_MSVC_FULL.match(name) or _RE_MSVC_SIMPLE.match(name)
        if not m:
            return None

        groups = m.groups()
        cls = groups[0]
        tpl = groups[1] if len(groups) > 2 else None
        method = groups[2] if len(groups) > 2 else groups[1]
        mtpl = groups[3] if len(groups) > 3 else None

        suffix = self._build_suffix(ea)
        parts = cls.split("::")
        base = parts[-1]

        if tpl:
            cls_enc = f"?${base}@{MSVC_TYPES.get(tpl, 'D')}@@"
        else:
            cls_enc = f"{base}@@"

        for ns in reversed(parts[:-1]):
            cls_enc = f"{ns}@{cls_enc}"

        if method == base:
            return f"??0{cls_enc}{suffix}"
        if method.startswith("~"):
            return f"??1{cls_enc}{suffix}"
        if method in MSVC_OPS:
            return f"{MSVC_OPS[method]}{cls_enc}{suffix}"
        if mtpl:
            return f"??${method}@{MSVC_TYPES.get(mtpl, 'D')}@{cls_enc}{suffix}"
        return f"?{method}@{cls_enc}{suffix}"

    def _mangle_free(self, name: str, ea: int) -> str | None:
        suffix = self._build_free_suffix(ea)
        return f"?{name}@@{suffix}"

    def _build_free_suffix(self, ea: int) -> str:
        default = "YAXXX@Z" if self.x64 else "YAXXX@Z"
        if not ea:
            return default

        ftype = guess_func_type(ea)
        if not ftype:
            return default

        params = _extract_params(ftype)
        ret_code = "X"

        if not params:
            return f"YA{ret_code}XZ"

        codes = [self._encode_type(p) for p in params]
        return f"YA{ret_code}{''.join(codes)}@Z"

    def _build_suffix(self, ea: int) -> str:
        default = "QEAAXXZ" if self.x64 else "QAEXXZ"
        if not ea:
            return default

        ftype = guess_func_type(ea)
        if not ftype:
            return default

        params = _extract_params(ftype)
        prefix = "QEAA" if self.x64 else "QAE"

        if not params:
            return f"{prefix}X@Z"

        codes = [self._encode_type(p) for p in params]
        return f"{prefix}{''.join(codes)}@Z"

    def _encode_type(self, t: str) -> str:
        if not t:
            return "X"
        t = t.strip()

        ptr = t.count("*")
        ref = "&" in t and "&&" not in t
        base = t.replace("*", "").replace("&", "")
        base = base.replace("const", "").replace("volatile", "").strip()

        if base in MSVC_TYPES:
            code = MSVC_TYPES[base]
        else:
            if ptr:
                return f"PEAV{base}@@" if self.x64 else f"PAV{base}@@"
            if ref:
                return f"AEAV{base}@@" if self.x64 else f"AAV{base}@@"
            return f"V{base}@@"

        if ptr:
            code = ("PEA" if self.x64 else "PA") + code
        elif ref:
            code = ("AEA" if self.x64 else "AA") + code
        return code


class ItaniumMangler:
    def mangle(self, name: str, ea: int = 0) -> str | None:
        if not name:
            return None

        if "::" not in name:
            params = self._build_params(ea)
            return f"_Z{len(name)}{name}{params}"

        m = _RE_ITANIUM.match(name)
        if not m:
            return None

        cls, method = m.groups()
        parts = cls.split("::")
        nested = "".join(f"{len(p)}{p}" for p in parts)

        if method.startswith("~"):
            mcode = "D1"
        elif method == parts[-1]:
            mcode = "C1"
        elif method in ITANIUM_OPS:
            mcode = ITANIUM_OPS[method]
        else:
            mcode = f"{len(method)}{method}"

        params = self._build_params(ea)
        return f"_ZN{nested}{mcode}E{params}"

    def _build_params(self, ea: int) -> str:
        if not ea:
            return "v"

        ftype = guess_func_type(ea)
        if not ftype:
            return "v"

        params = _extract_params(ftype)
        if not params:
            return "v"

        result = ""
        for p in params:
            p = p.strip()
            if p.endswith("*"):
                result += "P" + self._encode_type(p[:-1].strip())
            elif p.endswith("&"):
                result += "R" + self._encode_type(p[:-1].strip())
            else:
                result += self._encode_type(p)
        return result or "v"

    def _encode_type(self, t: str) -> str:
        t = t.replace("const", "").strip()
        return ITANIUM_TYPES.get(t, f"{len(t)}{t}")


class SymbolChooser(ida_kernwin.Choose):
    def __init__(self, filter_text: str = "") -> None:
        title = "Mangled Symbols"
        if filter_text:
            title += f" [{filter_text}]"
        super().__init__(title, [
            ["Address", 14], ["Scheme", 10], ["Mangled", 40], ["Demangled", 60]
        ], flags=ida_kernwin.CH_CAN_REFRESH)
        self.items: list[list[str]] = []
        self.filter_text = filter_text.lower()
        self._load()

    def _load(self) -> None:
        self.items = []
        for ea, name in idautils.Names():
            scheme = detect_scheme(name)
            if scheme == Scheme.UNKNOWN:
                continue
            dem = demangle(name) or "(failed)"
            if self.filter_text:
                searchable = f"{name} {dem}".lower()
                if self.filter_text not in searchable:
                    continue
            self.items.append([
                hex(ea), SCHEME_NAMES[scheme],
                name[:60], dem[:80]
            ])

    def OnGetSize(self) -> int:
        return len(self.items)

    def OnGetLine(self, n: int) -> list[str]:
        return self.items[n] if 0 <= n < len(self.items) else []

    def OnSelectLine(self, n: int):
        if 0 <= n < len(self.items):
            ida_kernwin.jumpto(int(self.items[n][0], 16))
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnRefresh(self, n: int):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED]


class RenameHandler(idaapi.action_handler_t):
    def __init__(self, undo: UndoManager) -> None:
        super().__init__()
        self.msvc = MSVCMangler()
        self.itanium = ItaniumMangler()
        self._undo = undo

    def activate(self, ctx) -> int:
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            return 1

        old_name = ida_name.get_name(ea) or ""

        prefill = ""
        if old_name:
            scheme = detect_scheme(old_name)
            if scheme != Scheme.UNKNOWN:
                prefill = demangle(old_name) or ""

        inp = ida_kernwin.ask_str(prefill, 0, "Enter function name:")
        if not inp:
            return 1

        inp = inp.strip()
        scheme = detect_scheme(inp)

        if scheme != Scheme.UNKNOWN:
            self._apply_mangled(ea, inp, old_name, scheme)
        elif "::" in inp:
            self._mangle_and_apply(ea, inp, old_name)
        else:
            self._apply_plain(ea, inp, old_name)

        self._refresh_views()
        return 1

    @staticmethod
    def _refresh_views() -> None:
        ida_kernwin.refresh_idaview_anyway()
        try:
            widget = ida_kernwin.find_widget("Pseudocode-A")
            if widget:
                ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

    def _apply_plain(self, ea: int, name: str, old: str) -> None:
        safe = sanitize(name)
        flags = ida_name.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_PUBLIC
        if ida_name.set_name(ea, safe, flags):
            ftype = guess_func_type(ea)
            if ftype:
                idc.set_cmt(ea, ftype, 0)
            self._undo.record(ea, old, safe)

    def _apply_mangled(self, ea: int, name: str, old: str, scheme: Scheme) -> None:
        flags = ida_name.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_PUBLIC
        if ida_name.set_name(ea, name, flags):
            dem = demangle(name)
            idc.set_cmt(ea, f"[{SCHEME_NAMES[scheme]}] {dem or ''}", 0)
            self._undo.record(ea, old, name)

    def _mangle_and_apply(self, ea: int, cpp_name: str, old: str) -> None:
        compiler = detect_compiler()
        if compiler == Scheme.ITANIUM:
            mangled = (self.itanium.mangle(cpp_name, ea) or
                       self.msvc.mangle(cpp_name, ea))
        else:
            mangled = (self.msvc.mangle(cpp_name, ea) or
                       self.itanium.mangle(cpp_name, ea))

        flags = ida_name.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_PUBLIC
        if mangled:
            if ida_name.set_name(ea, mangled, flags):
                idc.set_cmt(ea, cpp_name, 0)
                self._undo.record(ea, old, mangled)
        else:
            self._apply_plain(ea, cpp_name, old)

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class InfoHandler(idaapi.action_handler_t):
    def activate(self, ctx) -> int:
        ea = ida_kernwin.get_screen_ea()
        name = ida_name.get_name(ea)
        if not name:
            ida_kernwin.warning("No symbol at current address.")
            return 1

        scheme = detect_scheme(name)
        dem = demangle(name)
        ftype = guess_func_type(ea)

        info_lines = [
            f"Address:    {hex(ea)}",
            f"Symbol:     {name}",
            f"Scheme:     {SCHEME_NAMES[scheme]}",
            f"Demangled:  {dem or '(none)'}",
            f"Type:       {ftype or '(unknown)'}",
        ]
        ida_kernwin.info("\n".join(info_lines))
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class UndoHandler(idaapi.action_handler_t):
    def __init__(self, undo: UndoManager) -> None:
        super().__init__()
        self._undo = undo

    def activate(self, ctx) -> int:
        rec = self._undo.undo()
        if rec:
            ida_kernwin.info(
                f"Restored: {rec.old_name}\n"
                f"At: {hex(rec.ea)}\n"
                f"(was: {rec.new_name})"
            )
            ida_kernwin.jumpto(rec.ea)
        else:
            ida_kernwin.warning("Nothing to undo.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE if self._undo.can_undo() else idaapi.AST_DISABLE


class BrowseHandler(idaapi.action_handler_t):
    def activate(self, ctx) -> int:
        filter_text = ida_kernwin.ask_str("", 0, "Filter symbols (leave empty for all):")
        if filter_text is None:
            return 1
        SymbolChooser(filter_text.strip()).Show()
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class BatchDemangleHandler(idaapi.action_handler_t):
    def activate(self, ctx) -> int:
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Batch Demangle All Symbols?\n\n"
            "This will add demangled names as comments\n"
            "to all mangled symbols in the binary.\n\n"
            "Continue?"
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return 1

        ida_kernwin.show_wait_box("Demangling symbols...")

        stats = {s: 0 for s in Scheme}
        total = 0
        success = 0
        failed = 0

        try:
            names_list = list(idautils.Names())
            count = len(names_list)

            for idx, (ea, name) in enumerate(names_list):
                if ida_kernwin.user_cancelled():
                    break

                if idx % 500 == 0:
                    ida_kernwin.replace_wait_box(
                        f"Processing {idx}/{count} symbols..."
                    )

                scheme = detect_scheme(name)
                if scheme == Scheme.UNKNOWN:
                    continue

                total += 1
                stats[scheme] += 1
                dem = demangle(name)

                if dem:
                    idc.set_cmt(ea, f"[{SCHEME_NAMES[scheme]}] {dem}", 1)
                    success += 1
                else:
                    failed += 1
        finally:
            ida_kernwin.hide_wait_box()

        lines = [
            f"Batch Demangle Complete",
            f"",
            f"Total mangled:  {total}",
            f"Demangled OK:   {success}",
            f"Failed:         {failed}",
            f"",
            f"By scheme:",
        ]
        for scheme, cnt in stats.items():
            if cnt > 0:
                lines.append(f"  {SCHEME_NAMES[scheme]}: {cnt}")

        ida_kernwin.info("\n".join(lines))
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class StatsHandler(idaapi.action_handler_t):
    def activate(self, ctx) -> int:
        ida_kernwin.show_wait_box("Analyzing symbols...")

        stats = {s: 0 for s in Scheme}
        demangled_ok = 0
        demangled_fail = 0
        total = 0

        try:
            for ea, name in idautils.Names():
                if ida_kernwin.user_cancelled():
                    break
                scheme = detect_scheme(name)
                if scheme == Scheme.UNKNOWN:
                    continue
                total += 1
                stats[scheme] += 1
                if demangle(name):
                    demangled_ok += 1
                else:
                    demangled_fail += 1
        finally:
            ida_kernwin.hide_wait_box()

        lines = [
            f"Symbol Statistics",
            f"",
            f"Total mangled symbols:  {total}",
            f"Demangling success:     {demangled_ok}",
            f"Demangling failed:      {demangled_fail}",
            f"Success rate:           {demangled_ok * 100 // max(total, 1)}%",
            f"",
            f"Breakdown by scheme:",
        ]
        for scheme in Scheme:
            if stats[scheme] > 0:
                pct = stats[scheme] * 100 // max(total, 1)
                lines.append(
                    f"  {SCHEME_NAMES[scheme]:>12}: {stats[scheme]:>6}  ({pct}%)"
                )

        ida_kernwin.info("\n".join(lines))
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class MenuHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = idaapi.get_widget_type(widget)
        if wtype in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
            idaapi.attach_action_to_popup(widget, popup, ActionID.RENAME, "Demangler/")
            idaapi.attach_action_to_popup(widget, popup, ActionID.INFO, "Demangler/")
            idaapi.attach_action_to_popup(widget, popup, ActionID.UNDO, "Demangler/")
            idaapi.attach_action_to_popup(widget, popup, ActionID.BATCH, "Demangler/")


class DemanglerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Multi-Language Name Demangler with Auto Arg Detection"
    help = (
        f"Shift+N: Rename | Ctrl+Shift+N: Info | Ctrl+Shift+Z: Undo\n"
        f"Ctrl+Alt+N: Browse | Ctrl+Shift+D: Batch | Ctrl+Alt+S: Stats"
    )
    wanted_name = "Demangler"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self.hooks: MenuHook | None = None
        self.undo = UndoManager()

    def init(self) -> int:
        actions = [
            (ActionID.RENAME, "C++ Rename (Auto Args)...",
             RenameHandler(self.undo), Hotkey.RENAME),
            (ActionID.INFO, "Symbol Info",
             InfoHandler(), Hotkey.INFO),
            (ActionID.UNDO, "Undo Rename",
             UndoHandler(self.undo), Hotkey.UNDO),
            (ActionID.BROWSE, "Browse Symbols...",
             BrowseHandler(), Hotkey.BROWSE),
            (ActionID.BATCH, "Batch Demangle All...",
             BatchDemangleHandler(), Hotkey.BATCH),
            (ActionID.STATS, "Symbol Statistics",
             StatsHandler(), Hotkey.STATS),
        ]

        for aid, label, handler, hotkey in actions:
            desc = idaapi.action_desc_t(aid, label, handler, hotkey, "", -1)
            idaapi.register_action(desc)

        self.hooks = MenuHook()
        self.hooks.hook()

        print(
            f"[Demangler] v{PLUGIN_VERSION} loaded | "
            f"{Hotkey.RENAME}: Rename | "
            f"{Hotkey.BROWSE}: Browse | "
            f"{Hotkey.BATCH}: Batch"
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        idaapi.process_ui_action(ActionID.RENAME)

    def term(self) -> None:
        if self.hooks:
            self.hooks.unhook()
        for aid in ActionID.ALL:
            idaapi.unregister_action(aid)


def PLUGIN_ENTRY():
    return DemanglerPlugin()
