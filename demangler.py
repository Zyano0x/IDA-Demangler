import ida_kernwin
import ida_name
import ida_typeinf
import idaapi
import idc
import re


OPERATORS = {
    'operator=': '??4',
    'operator==': '??8',
    'operator!=': '??9',
    'operator[]': '??A',
    'operator->': '??C',
    'operator*': '??D',
    'operator++': '??E',
    'operator--': '??F',
    'operator-': '??G',
    'operator+': '??H',
    'operator&': '??I',
    'operator/': '??K',
    'operator%': '??L',
    'operator<': '??M',
    'operator<=': '??N',
    'operator>': '??O',
    'operator>=': '??P',
    'operator()': '??R',
    'operator~': '??S',
    'operator^': '??T',
    'operator|': '??U',
    'operator<<': '??6',
    'operator>>': '??5',
}

TYPE_MAP = {
    'char': 'D',
    'unsigned char': 'E',
    'short': 'F',
    'unsigned short': 'G',
    'int': 'H',
    'unsigned int': 'I',
    'long': 'J',
    'unsigned long': 'K',
    'float': 'M',
    'double': 'N',
    'bool': '_N',
    'void': 'X',
    'wchar_t': '_W',
}

CPP_NAME_PATTERN = re.compile(r'^([\w]+)(?:<([^>]+)>)?::([\w]+|operator.+)$')


class Demangler:
    
    @staticmethod
    def demangle(mangled_name):
        result = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if result:
            return result
        return idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DN))
    
    @staticmethod
    def get_mangled(ea):
        name = ida_name.get_name(ea)
        return name if name and name.startswith('?') else None
    
    @staticmethod
    def mangle(class_name, method_name, is_template=False, template_param=None):
        is_64bit = idaapi.inf_is_64bit()
        
        if is_template and template_param:
            type_code = TYPE_MAP.get(template_param, 'D')
            class_part = f"?${class_name}@{type_code}@@"
        else:
            class_part = f"{class_name}@@"
        
        prefix = OPERATORS.get(method_name, f"?{method_name}")
        mangled = f"{prefix}@{class_part}"
        
        if method_name == 'operator=':
            suffix = "QEAAAEAV0@AEBV0@@Z" if is_64bit else "QAEAAV0@ABV0@@Z"
        elif method_name.startswith('operator'):
            suffix = "QEAA?AV0@ABV0@@Z" if is_64bit else "QAE?AV0@ABV0@@Z"
        else:
            suffix = "QEAAXXZ" if is_64bit else "QAEXXZ"
        
        return mangled + suffix


class CppRenameAction(idaapi.action_handler_t):
    
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        current_name = ida_name.get_name(ea)
        current_demangled = None
        
        if current_name and current_name.startswith('?'):
            current_demangled = Demangler.demangle(current_name)
            if current_demangled:
                ida_kernwin.info(
                    f"Mangled: {current_name}\n\n"
                    f"Demangled: {current_demangled}"
                )
        
        user_input = ida_kernwin.ask_str(
            current_demangled or "", 0, 
            "Enter C++ name or mangled name:"
        )
        
        if not user_input:
            return 1
        
        if user_input.startswith('?'):
            self._apply_mangled(ea, user_input)
        else:
            self._apply_cpp_name(ea, user_input)
        
        return 1
    
    def _apply_mangled(self, ea, mangled):
        demangled = Demangler.demangle(mangled)
        if demangled:
            ida_name.set_name(ea, mangled, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
            idc.set_cmt(ea, f"Demangled: {demangled}", 0)
        else:
            ida_kernwin.warning(f"Could not demangle: {mangled}")
    
    def _apply_cpp_name(self, ea, cpp_name):
        match = CPP_NAME_PATTERN.match(cpp_name)
        
        if not match:
            ida_name.set_name(ea, cpp_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
            return
        
        class_name, template_param, method_name = match.groups()
        mangled = Demangler.mangle(
            class_name, method_name,
            is_template=template_param is not None,
            template_param=template_param
        )
        
        if ida_name.set_name(ea, mangled, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
            idc.set_cmt(ea, f"C++ name: {cpp_name}", 0)
        else:
            simple_name = cpp_name.replace('::', '_').replace('<', '_').replace('>', '_')
            ida_name.set_name(ea, simple_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
            idc.set_cmt(ea, f"C++ name: {cpp_name}\nMangled: {mangled}", 0)
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DemanglerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "C++ Name Mangler/Demangler"
    help = "Shift+N: Convert C++ names to/from mangled names"
    wanted_name = "Demangler"
    wanted_hotkey = ""
    
    ACTION_NAME = "demangler:rename"
    ACTION_LABEL = "C++ Rename..."
    ACTION_HOTKEY = "Shift+N"
    
    def init(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_NAME,
            self.ACTION_LABEL,
            CppRenameAction(),
            self.ACTION_HOTKEY,
            "Convert between C++ and mangled names",
            -1
        )
        
        if idaapi.register_action(action_desc):
            print(f"[Demangler] Loaded - Press {self.ACTION_HOTKEY}")
            return idaapi.PLUGIN_KEEP
        
        print("[Demangler] Failed to register")
        return idaapi.PLUGIN_SKIP
    
    def run(self, arg):
        idaapi.process_ui_action(self.ACTION_NAME)
    
    def term(self):
        idaapi.unregister_action(self.ACTION_NAME)


def PLUGIN_ENTRY():
    return DemanglerPlugin()
