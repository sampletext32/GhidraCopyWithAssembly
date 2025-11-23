from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

def copy_to_clipboard(text):
    clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
    clipboard.setContents(StringSelection(text), None)

def get_decompiled_c(func):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)  # Initialize with current program
    
    # Set decompiler options (optional)
    options = decompiler.getOptions()
    # options.setIgnoreUnimplemented(True)  # Skip unimplemented features
    
    # Decompile the function
    decompile_results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
    if not decompile_results.decompileCompleted():
        return "// Decompilation failed: {}".format(decompile_results.getErrorMessage())
    
    return decompile_results.getDecompiledFunction().getC()

def run():
    current_address = currentLocation.getAddress()
    if not current_address:
        print("No active location found.")
        return
    
    func = getFunctionContaining(current_address)
    if not func:
        print("No function found at the current address.")
        return
    
    # Get assembly code (your existing logic)
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(func.getBody(), True)
    assembly_lines = ["{} {}".format(str(instr.getAddress()),str(instr)) for instr in instructions]
    
    # Get decompiled C code
    decompiled_c = get_decompiled_c(func)
    
    # Build output
    output = []
    output.append("// Decompiled C Code:")
    output.append(decompiled_c)
    output.append("\n---")
    output.append("\n// Assembly:")
    output.extend(assembly_lines)
    
    # Copy to clipboard
    copy_to_clipboard("\n".join(output))
    print("Copied decompilation and assembly of '{}' to clipboard!".format(func.getName()))

if __name__ == "__main__":
    run()
