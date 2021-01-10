from extraction import *
import ghidra
import docking
import json

decomp = ghidra.app.decompiler.DecompInterface()
decomp.openProgram(currentProgram)

def extract_fn(fn):
    hf = decomp.decompileFunction(fn, 30, monitor).getHighFunction()
    return extract(list(hf.getPcodeOps()))

fns = {}
for fn in currentProgram.getFunctionManager().getFunctions(True):
    fns[fn.name] = {
        'name': fn.name,
        'address': extract(fn.entryPoint),
        'pcodes': extract_fn(fn),
    }

fileChooser = docking.widgets.filechooser.GhidraFileChooser(None)
with open(str(fileChooser.getSelectedFile(True)), 'w') as f:
    json.dump(fns, f)
