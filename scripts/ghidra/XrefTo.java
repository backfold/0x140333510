// XrefTo.java — 주어진 VA로의 모든 레퍼런스 출력
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class XrefTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                println(a + " <- " + r.getFromAddress() + " type=" + r.getReferenceType());
                n++;
            }
            if (n == 0) println(a + " <- (레퍼런스 없음)");
        }
    }
}
