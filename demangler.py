"""
Multi-Language Name Demangler Plugin for IDA Pro v2.0
Supports: MSVC, GCC/Itanium, Rust, D, Borland
"""

import ida_kernwin
import ida_name
import idaapi
import idautils
import idc
import re
from enum import Enum, auto
from typing import Optional, Tuple, NamedTuple
from collections import deque

PLUGIN_VERSION = "2.0"
MAX_UNDO_HISTORY = 100


class RenameRecord(NamedTuple):
    ea: int
    old_name: str
    new_name: str


class UndoManager:
    def __init__(self, max_size=MAX_UNDO_HISTORY):
        self._history = deque(maxlen=max_size)
    
    def record(self, ea, old_name, new_name):
        self._history.append(RenameRecord(ea, old_name, new_name))
    
    def undo(self):
        if not self._history:
            return None
        record = self._history.pop()
        if ida_name.set_name(record.ea, record.old_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            idc.set_cmt(record.ea, "", 0)
            return record
        return None
    
    def can_undo(self):
        return len(self._history) > 0


_undo = UndoManager()


class Scheme(Enum):
    UNKNOWN = auto()
    MSVC = auto()
    ITANIUM = auto()
    RUST_V0 = auto()
    RUST_LEGACY = auto()
    DLANG = auto()
    BORLAND = auto()


SCHEME_NAMES = {
    Scheme.UNKNOWN: "Unknown", Scheme.MSVC: "MSVC", Scheme.ITANIUM: "GCC/Clang",
    Scheme.RUST_V0: "Rust v0", Scheme.RUST_LEGACY: "Rust Legacy",
    Scheme.DLANG: "D", Scheme.BORLAND: "Borland",
}

MSVC_OPS = {
    'operator=': '??4', 'operator==': '??8', 'operator!=': '??9',
    'operator[]': '??A', 'operator->': '??C', 'operator*': '??D',
    'operator++': '??E', 'operator--': '??F', 'operator-': '??G',
    'operator+': '??H', 'operator&': '??I', 'operator/': '??K',
    'operator%': '??L', 'operator<': '??M', 'operator<=': '??N',
    'operator>': '??O', 'operator>=': '??P', 'operator()': '??R',
    'operator~': '??S', 'operator^': '??T', 'operator|': '??U',
    'operator<<': '??6', 'operator>>': '??5', 'operator!': '??7',
    'operator+=': '??Y', 'operator-=': '??Z', 'operator*=': '??X',
    'operator new': '??2', 'operator delete': '??3',
    'operator new[]': '??_U', 'operator delete[]': '??_V',
}

MSVC_TYPES = {
    'char': 'D', 'signed char': 'C', 'unsigned char': 'E',
    'short': 'F', 'unsigned short': 'G', 'int': 'H', 'unsigned int': 'I',
    'long': 'J', 'unsigned long': 'K', 'float': 'M', 'double': 'N',
    'long double': 'O', 'bool': '_N', 'void': 'X', 'wchar_t': '_W',
    '__int64': '_J', 'unsigned __int64': '_K',
    'long long': '_J', 'unsigned long long': '_K',
    'char16_t': '_S', 'char32_t': '_U',
    'BYTE': 'E', 'WORD': 'G', 'DWORD': 'K', 'QWORD': '_K',
    'BOOL': 'H', 'INT': 'H', 'UINT': 'I', 'LONG': 'J', 'ULONG': 'K',
}

ITANIUM_TYPES = {
    'void': 'v', 'bool': 'b', 'char': 'c', 'wchar_t': 'w',
    'signed char': 'a', 'unsigned char': 'h',
    'short': 's', 'unsigned short': 't', 'int': 'i', 'unsigned int': 'j',
    'long': 'l', 'unsigned long': 'm', 'long long': 'x', 'unsigned long long': 'y',
    'float': 'f', 'double': 'd', 'long double': 'e',
}

ITANIUM_OPS = {
    'operator new': 'nw', 'operator delete': 'dl', 'operator~': 'co',
    'operator+': 'pl', 'operator-': 'mi', 'operator*': 'ml', 'operator/': 'dv',
    'operator%': 'rm', 'operator&': 'an', 'operator|': 'or', 'operator^': 'eo',
    'operator=': 'aS', 'operator+=': 'pL', 'operator-=': 'mI',
    'operator==': 'eq', 'operator!=': 'ne', 'operator<': 'lt', 'operator>': 'gt',
    'operator<=': 'le', 'operator>=': 'ge', 'operator<<': 'ls', 'operator>>': 'rs',
    'operator++': 'pp', 'operator--': 'mm', 'operator()': 'cl', 'operator[]': 'ix',
}


def detect_scheme(name):
    if not name or len(name) < 2:
        return Scheme.UNKNOWN
    if name.startswith('?'):
        return Scheme.MSVC
    if name.startswith('_R') and len(name) > 2:
        return Scheme.RUST_V0
    if name.startswith('_Z'):
        if '$' in name or re.search(r'17h[0-9a-f]{16}E', name):
            return Scheme.RUST_LEGACY
        return Scheme.ITANIUM
    if name.startswith('_D') and len(name) > 2 and name[2].isdigit():
        return Scheme.DLANG
    if name.startswith('@'):
        return Scheme.BORLAND
    return Scheme.UNKNOWN


def detect_compiler():
    file_type = idaapi.get_file_type_name()
    if 'PE' in file_type or 'Windows' in file_type:
        return Scheme.MSVC
    if 'ELF' in file_type or 'Mach-O' in file_type:
        return Scheme.ITANIUM
    return Scheme.UNKNOWN


def demangle(name):
    if not name:
        return None
    try:
        result = idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))
        return result or idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    except:
        return None


def sanitize(name):
    if not name:
        return "unnamed"
    for old, new in [('::', '_'), ('<', '_'), ('>', '_'), (' ', '_'), ('*', 'p'), ('&', 'r')]:
        name = name.replace(old, new)
    while '__' in name:
        name = name.replace('__', '_')
    return name.strip('_') or "unnamed"


class MSVCMangler:
    PATTERN = re.compile(r'^((?:[\w]+::)*[\w]+)(?:<([^<>]+)>)?::([\w~]+|operator\S+?)(?:<([^<>]+)>)?$')
    SIMPLE = re.compile(r'^([\w]+)::([\w~]+|operator\S+)$')
    
    def __init__(self):
        self.x64 = idaapi.inf_is_64bit()
    
    def mangle(self, name, ea=0):
        if not name or '::' not in name:
            return None
        
        m = self.PATTERN.match(name) or self.SIMPLE.match(name)
        if not m:
            return None
        
        groups = m.groups()
        cls = groups[0]
        tpl = groups[1] if len(groups) > 2 else None
        method = groups[2] if len(groups) > 2 else groups[1]
        mtpl = groups[3] if len(groups) > 3 else None
        
        suffix = self._suffix(ea)
        parts = cls.split('::')
        base = parts[-1]
        
        if tpl:
            cls_enc = f"?${base}@{MSVC_TYPES.get(tpl, 'D')}@@"
        else:
            cls_enc = f"{base}@@"
        
        for ns in reversed(parts[:-1]):
            cls_enc = f"{ns}@{cls_enc}"
        
        if method == base:
            return f"??0{cls_enc}{suffix}"
        if method.startswith('~'):
            return f"??1{cls_enc}{suffix}"
        if method in MSVC_OPS:
            return f"{MSVC_OPS[method]}{cls_enc}{suffix}"
        if mtpl:
            return f"??${method}@{MSVC_TYPES.get(mtpl, 'D')}@{cls_enc}{suffix}"
        return f"?{method}@{cls_enc}{suffix}"
    
    def _suffix(self, ea):
        default = "QEAAXXZ" if self.x64 else "QAEXXZ"
        if not ea:
            return default
        
        ftype = idc.get_type(ea)
        if not ftype:
            return default
        
        m = re.search(r'\(([^)]*)\)', ftype)
        if not m:
            return default
        
        params = m.group(1).strip()
        prefix = "QEAA" if self.x64 else "QAE"
        
        if not params or params.lower() == 'void':
            return f"{prefix}X@Z"
        
        codes = []
        for i, p in enumerate(params.split(',')):
            p = p.strip().replace('const', '').replace('volatile', '').strip()
            if i == 0 and '*' in p:
                base = p.replace('*', '').strip()
                if base not in MSVC_TYPES:
                    continue
            codes.append(self._encode(p))
        
        return f"{prefix}{''.join(codes)}@Z" if codes else f"{prefix}X@Z"
    
    def _encode(self, t):
        if not t:
            return 'X'
        t = t.strip()
        ptr = t.count('*')
        ref = '&' in t and '&&' not in t
        base = t.replace('*', '').replace('&', '').strip()
        
        if base in MSVC_TYPES:
            code = MSVC_TYPES[base]
        else:
            if ptr:
                return f"PEAV{base}@@" if self.x64 else f"PAV{base}@@"
            if ref:
                return f"AEAV{base}@@" if self.x64 else f"AAV{base}@@"
            return f"V{base}@@"
        
        if ptr:
            code = ('PEA' if self.x64 else 'PA') + code
        elif ref:
            code = ('AEA' if self.x64 else 'AA') + code
        return code


class ItaniumMangler:
    PATTERN = re.compile(r'^((?:[\w]+::)*[\w]+)::([\w~]+|operator\S+?)$')
    
    def mangle(self, name, ea=0):
        if not name or '::' not in name:
            return None
        
        m = self.PATTERN.match(name)
        if not m:
            return None
        
        cls, method = m.groups()
        parts = cls.split('::')
        nested = ''.join(f"{len(p)}{p}" for p in parts)
        
        if method.startswith('~'):
            mcode = "D1"
        elif method == parts[-1]:
            mcode = "C1"
        elif method in ITANIUM_OPS:
            mcode = ITANIUM_OPS[method]
        else:
            mcode = f"{len(method)}{method}"
        
        params = self._params(ea)
        return f"_ZN{nested}{mcode}E{params}"
    
    def _params(self, ea):
        if not ea:
            return 'v'
        ftype = idc.get_type(ea)
        if not ftype:
            return 'v'
        
        m = re.search(r'\(([^)]*)\)', ftype)
        if not m:
            return 'v'
        
        params = m.group(1).strip()
        if not params or params.lower() == 'void':
            return 'v'
        
        result = ''
        for p in params.split(','):
            p = p.strip()
            if p.endswith('*'):
                result += 'P' + self._enc(p[:-1].strip())
            elif p.endswith('&'):
                result += 'R' + self._enc(p[:-1].strip())
            else:
                result += self._enc(p)
        return result or 'v'
    
    def _enc(self, t):
        t = t.replace('const', '').strip()
        return ITANIUM_TYPES.get(t, f"{len(t)}{t}")


class SymbolChooser(ida_kernwin.Choose):
    def __init__(self):
        super().__init__("Mangled Symbols", [
            ["Address", 14], ["Scheme", 10], ["Mangled", 40], ["Demangled", 60]
        ], flags=ida_kernwin.CH_CAN_REFRESH)
        self.items = []
        self._load()
    
    def _load(self):
        self.items = []
        for ea, name in idautils.Names():
            scheme = detect_scheme(name)
            if scheme != Scheme.UNKNOWN:
                dem = demangle(name) or "(failed)"
                self.items.append([hex(ea), SCHEME_NAMES[scheme], name[:50], dem[:70]])
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        return self.items[n] if 0 <= n < len(self.items) else []
    
    def OnSelectLine(self, n):
        if 0 <= n < len(self.items):
            ida_kernwin.jumpto(int(self.items[n][0], 16))
        return (ida_kernwin.Choose.NOTHING_CHANGED,)
    
    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED]


class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
        self.msvc = MSVCMangler()
        self.itanium = ItaniumMangler()
    
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            return 1
        
        old_name = ida_name.get_name(ea) or ""
        demangled = None
        
        if old_name:
            scheme = detect_scheme(old_name)
            if scheme != Scheme.UNKNOWN:
                demangled = demangle(old_name)
                if demangled:
                    ida_kernwin.info(f"Scheme: {SCHEME_NAMES[scheme]}\nMangled: {old_name}\nDemangled: {demangled}")
        
        inp = ida_kernwin.ask_str(demangled or "", 0, "C++ name (Class::Method) or mangled:")
        if not inp:
            return 1
        
        inp = inp.strip()
        scheme = detect_scheme(inp)
        
        if scheme != Scheme.UNKNOWN:
            self._set(ea, inp, old_name, scheme)
        else:
            self._mangle(ea, inp, old_name)
        return 1
    
    def _set(self, ea, name, old, scheme):
        if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_PUBLIC):
            dem = demangle(name)
            idc.set_cmt(ea, f"[{SCHEME_NAMES[scheme]}] {dem or ''}", 0)
            _undo.record(ea, old, name)
    
    def _mangle(self, ea, cpp_name, old):
        compiler = detect_compiler()
        if compiler == Scheme.ITANIUM:
            mangled = self.itanium.mangle(cpp_name, ea) or self.msvc.mangle(cpp_name, ea)
        else:
            mangled = self.msvc.mangle(cpp_name, ea) or self.itanium.mangle(cpp_name, ea)
        
        if mangled:
            if ida_name.set_name(ea, mangled, ida_name.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_PUBLIC):
                idc.set_cmt(ea, cpp_name, 0)
                _undo.record(ea, old, mangled)
        else:
            safe = sanitize(cpp_name)
            ida_name.set_name(ea, safe, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
            idc.set_cmt(ea, cpp_name, 0)
            _undo.record(ea, old, safe)
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class InfoHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        name = ida_name.get_name(ea)
        if not name:
            ida_kernwin.info("No symbol at address")
            return 1
        
        scheme = detect_scheme(name)
        dem = demangle(name)
        ida_kernwin.info(
            f"Address: {hex(ea)}\n"
            f"Symbol: {name}\n"
            f"Scheme: {SCHEME_NAMES[scheme]}\n"
            f"Demangled: {dem or '(none)'}"
        )
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class UndoHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        rec = _undo.undo()
        if rec:
            ida_kernwin.info(f"Restored: {rec.old_name} at {hex(rec.ea)}")
            ida_kernwin.jumpto(rec.ea)
        else:
            ida_kernwin.info("Nothing to undo")
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE if _undo.can_undo() else idaapi.AST_DISABLE


class BrowseHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        SymbolChooser().Show()
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MenuHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]:
            idaapi.attach_action_to_popup(widget, popup, "dem:rename", "Demangler/")
            idaapi.attach_action_to_popup(widget, popup, "dem:info", "Demangler/")


class DemanglerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Multi-Language Name Demangler"
    help = "Shift+N: Rename | Ctrl+Shift+N: Info | Ctrl+Alt+N: Browse"
    wanted_name = "Demangler"
    wanted_hotkey = ""
    
    def __init__(self):
        self.hooks = None
    
    def init(self):
        actions = [
            ("dem:rename", "C++ Rename...", RenameHandler(), "Shift+N"),
            ("dem:info", "Symbol Info", InfoHandler(), "Ctrl+Shift+N"),
            ("dem:undo", "Undo Rename", UndoHandler(), "Ctrl+Shift+Z"),
            ("dem:browse", "Browse Symbols", BrowseHandler(), "Ctrl+Alt+N"),
        ]
        
        for aid, label, handler, hotkey in actions:
            idaapi.register_action(idaapi.action_desc_t(aid, label, handler, hotkey, "", -1))
        
        self.hooks = MenuHook()
        self.hooks.hook()
        
        print(f"[Demangler] v{PLUGIN_VERSION} | Shift+N: Rename | Ctrl+Alt+N: Browse")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        idaapi.process_ui_action("dem:rename")
    
    def term(self):
        if self.hooks:
            self.hooks.unhook()
        for a in ["dem:rename", "dem:info", "dem:undo", "dem:browse"]:
            idaapi.unregister_action(a)


def PLUGIN_ENTRY():
    return DemanglerPlugin()
