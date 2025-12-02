# -*- coding: utf-8 -*-
# Export struct under cursor in decompiler (Ghidra 11.4.x, token-based)
# @category Data Types

from ghidra.app.script import GhidraScript
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from ghidra.program.model.data import (
    Structure, Array, Pointer, TypeDef, FunctionDefinition
)


def copy_to_clipboard(text):
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
        StringSelection(text), None
    )


# -------------------------------------------------------------
# TYPE CONVERSION
# -------------------------------------------------------------

def function_pointer_to_c(funcdef, name):
    """Generate C function pointer including calling convention."""
    ret = fieldtype_to_c(funcdef.getReturnType())

    # calling convention
    cc = funcdef.getCallingConventionName()
    if cc is None:
        cc_text = ""
    else:
        # normalize: "__stdcall", "__cdecl", "__thiscall", "__fastcall"
        cc_text = " %s" % cc

    # parameters
    params = []
    for p in funcdef.getArguments():
        ptype = fieldtype_to_c(p.getDataType())
        pname = p.getName() or ""
        params.append("%s %s" % (ptype, pname))

    if funcdef.hasVarArgs():
        params.append("...")

    param_text = ", ".join(params) if params else "void"

    # final form:
    # return_type <callingconvention> (*name)(params)
    return "%s%s (*%s)(%s)" % (ret, cc_text, name, param_text)

def fieldtype_to_c(dt):
    # unwrap all array dimensions
    if isinstance(dt, Array):
        dims = []
        base = dt
        while isinstance(base, Array):
            dims.append(base.getNumElements())
            base = base.getDataType()

        base_text = fieldtype_to_c(base)
        for n in dims:           # outermost → innermost
            base_text += "[%d]" % n
        return base_text

    if isinstance(dt, Structure):
        return dt.getName()
    if isinstance(dt, Pointer):
        base = dt.getDataType()
        if isinstance(base, FunctionDefinition):
            return None
        return fieldtype_to_c(base) + " *"
    if isinstance(dt, TypeDef):
        return dt.getName()
    return dt.getName()


def struct_to_c(s):
    lines = ["typedef struct %s {" % s.getName()]

    for comp in s.getComponents():
        dt = comp.getDataType()
        name = comp.getFieldName() or ("field_%d" % comp.getOffset())

        if isinstance(dt, Pointer) and isinstance(dt.getDataType(), FunctionDefinition):
            lines.append("    %s;" % function_pointer_to_c(dt.getDataType(), name))
        else:
            lines.append("    %s %s;" % (fieldtype_to_c(dt), name))

    lines.append("} %s;" % s.getName())
    return "\n".join(lines)


# -------------------------------------------------------------
# GET STRUCT UNDER CURSOR (GHIDRA 11.4+ token API)
# -------------------------------------------------------------

def get_struct_from_cursor():
    loc = currentLocation
    if loc is None:
        return None

    token = None
    try:
        token = loc.getToken()
    except:
        token = None

    if token is None:
        return None

    # Try all known datatype access paths
    dt = None

    # 1. Token direct type
    try:
        dt = token.getDataType()
    except:
        dt = None

    # 2. HighType
    if dt is None:
        try:
            ht = token.getHighType()
            if ht is not None:
                dt = ht.getDataType()
        except:
            pass

    # 3. HighVariable
    if dt is None:
        try:
            hv = token.getHighVariable()
            if hv is not None:
                dt = hv.getDataType()
        except:
            pass

    if dt is None:
        return None

    # unwrap typedefs/pointers
    base = dt
    while isinstance(base, (Pointer, TypeDef)):
        base = base.getDataType()

    if isinstance(base, Structure):
        return base

    return None


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------

def run():
    s = get_struct_from_cursor()
    if s is None:
        popup("Cursor is not on a struct in decompiler.")
        return

    text = struct_to_c(s)
    copy_to_clipboard(text)
    print("Exported struct '%s'." % s.getName())


if __name__ == "__main__":
    run()
