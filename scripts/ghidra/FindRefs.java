import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class FindRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        AddressFactory af = currentProgram.getAddressFactory();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String a : args) {
            Address target = af.getAddress(a);
            println("=== refs to " + a + " ===");
            ReferenceIterator it = rm.getReferencesTo(target);
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                println("  " + r.getFromAddress() + " " + r.getReferenceType() + " @ " +
                    currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress()));
                n++;
                if (n > 30) { println("  ..."); break; }
            }
            if (n == 0) println("  (none)");
        }
    }
}
