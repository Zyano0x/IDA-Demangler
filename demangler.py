import ida_kernwin
import ida_name
import idaapi
import idc
import re


OPERATORS = {
    'operator=': '??4', 'operator==': '??8', 'operator!=': '??9',
    'operator[]': '??A', 'operator->': '??C', 'operator*': '??D',
    'operator++': '??E', 'operator--': '??F', 'operator-': '??G',
    'operator+': '??H', 'operator&': '??I', 'operator/': '??K',
    'operator%': '??L', 'operator<': '??M', 'operator<=': '??N',
    'operator>': '??O', 'operator>=': '??P', 'operator()': '??R',
    'operator~': '??S', 'operator^': '??T', 'operator|': '??U',
    'operator<<': '??6', 'operator>>': '??5',
}

TYPE_MAP = {
    'char': 'D', 'unsigned char': 'E', 'short': 'F', 'unsigned short': 'G',
    'int': 'H', 'unsigned int': 'I', 'long': 'J', 'unsigned long': 'K',
    'float': 'M', 'double': 'N', 'bool': '_N', 'void': 'X', 'wchar_t': '_W',
    '__int64': '_J', 'unsigned __int64': '_K', 'long long': '_J',
    'unsigned long long': '_K', 'size_t': '_K', 'DWORD': 'K', 'BYTE': 'E',
    'WORD': 'G', 'BOOL': 'H',
}

CPP_NAME_PATTERN = re.compile(r'^([\w]+)(?:<([^>]+)>)?::([\w~]+|operator.+?)(?:<([^>]+)>)?$')


class Demangler:
    
    @staticmethod
    def demangle(mangled_name):
        result = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DN))
        return result or idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_SHORT_DN))
    
    @staticmethod
    def encode_type(type_str):
        """Encode a C++ type to MSVC mangled code."""
        type_str = type_str.strip()
        
        # Handle pointers and references
        ptr_count = type_str.count('*')
        is_ref = '&' in type_str
        base = type_str.replace('*', '').replace('&', '').strip()
        
        # Check TYPE_MAP first
        if base in TYPE_MAP:
            code = TYPE_MAP[base]
        else:
            # Unknown type - encode as class pointer
            code = f"PAV{base}@@" if ptr_count else f"V{base}@@"
            return code
        
        # Add pointer encoding
        if ptr_count:
            code = 'P' * ptr_count + 'EA' + code if idaapi.inf_is_64bit() else 'P' * ptr_count + 'A' + code
        elif is_ref:
            code = 'AEA' + code if idaapi.inf_is_64bit() else 'AA' + code
        
        return code
    
    @staticmethod
    def build_type_suffix(ea):
        """Build mangled type suffix from function's actual type."""
        is_64bit = idaapi.inf_is_64bit()
        func_type = idc.get_type(ea)
        
        if not func_type:
            return "QEAAXXZ" if is_64bit else "QAEXXZ"
        
        match = re.search(r'\(([^)]*)\)', func_type)
        if not match:
            return "QEAAXXZ" if is_64bit else "QAEXXZ"
        
        params_str = match.group(1).strip()
        prefix = "QEAA" if is_64bit else "QAE"
        
        if not params_str or params_str == 'void':
            return f"{prefix}X@Z"
        
        params = [p.strip() for p in params_str.split(',')]
        param_codes = []
        
        for i, param in enumerate(params):
            # Skip 'this' pointer
            if i == 0 and '*' in param and any(kw in param.lower() for kw in ['this', 'self']):
                continue
            if i == 0 and '*' in param and not any(t in param for t in TYPE_MAP):
                continue
            
            param_codes.append(Demangler.encode_type(param))
        
        if not param_codes:
            return f"{prefix}X@Z"
        
        return f"{prefix}@{''.join(param_codes)}@Z"
    
    @staticmethod
    def mangle(class_name, method_name, is_template=False, template_param=None, 
               method_template_param=None, type_suffix=None):
        """
        Build MSVC mangled name.
        For ZXString<unsigned short>::Assign<char>:
          - method_template: ??$Assign@D
          - class_template: @?$ZXString@G@@
          - Result: ??$Assign@D@?$ZXString@G@@QEAAXXZ
        """
        # Build class part
        if is_template and template_param:
            type_code = TYPE_MAP.get(template_param, 'D')
            class_part = f"?${class_name}@{type_code}@@"
        else:
            class_part = f"{class_name}@@"
        
        # Build method prefix
        if method_name == class_name:
            prefix = "??0"  # Constructor
            return f"{prefix}{class_part}{type_suffix or ''}"
        elif method_name == f"~{class_name}" or method_name.startswith('~'):
            prefix = "??1"  # Destructor
            return f"{prefix}{class_part}{type_suffix or ''}"
        
        # Handle method template: ??$MethodName@TypeCode@ClassName@@
        if method_template_param:
            method_type_code = TYPE_MAP.get(method_template_param, 'D')
            return f"??${method_name}@{method_type_code}@{class_part}{type_suffix or ''}"
        
        # Handle operators
        if method_name in OPERATORS:
            return f"{OPERATORS[method_name]}{class_part}{type_suffix or ''}"
        
        # Regular method: ?MethodName@ClassName@@
        return f"?{method_name}@{class_part}{type_suffix or ''}"


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
                ida_kernwin.info(f"Mangled: {current_name}\n\nDemangled: {current_demangled}")
        
        user_input = ida_kernwin.ask_str(current_demangled or "", 0, "Enter C++ name or mangled name:")
        
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
        
        class_name, template_param, method_name, method_template_param = match.groups()
        
        # Get type suffix from function or existing name
        type_suffix = Demangler.build_type_suffix(ea)
        if not type_suffix:
            current_name = ida_name.get_name(ea)
            if current_name and current_name.startswith('?'):
                suffix_match = re.search(r'@@(.+)$', current_name)
                if suffix_match:
                    type_suffix = suffix_match.group(1)
        
        mangled = Demangler.mangle(
            class_name, method_name,
            is_template=template_param is not None,
            template_param=template_param,
            method_template_param=method_template_param,
            type_suffix=type_suffix
        )
        
        if ida_name.set_name(ea, mangled, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
            idc.set_cmt(ea, f"C++ name: {cpp_name}", 0)
        else:
            simple_name = cpp_name.replace('::', '_').replace('<', '_').replace('>', '_').replace(' ', '_')
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
            self.ACTION_NAME, self.ACTION_LABEL, CppRenameAction(),
            self.ACTION_HOTKEY, "Convert between C++ and mangled names", -1
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
