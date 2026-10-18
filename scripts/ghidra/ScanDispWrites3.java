// ScanDispWrites3.java — disp ∈ [0xe8..0x108] ∪ [0x1b0..0x1d8] 쓰기 전수 출력 (bulk 쓰기 커버 확인용)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

public class ScanDispWrites3 extends GhidraScript {
    static boolean inWin(long v) {
        return (v >= 0xe8 && v <= 0x108) || (v >= 0x1b0 && v <= 0x1d8);
    }
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address text = mem.getBlock(".text").getStart();
        Address textEnd = mem.getBlock(".text").getEnd();
        InstructionIterator it = currentProgram.getListing().getInstructions(text, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(textEnd) > 0) break;
            String mn = ins.getMnemonicString();
            if (mn.startsWith("J") || mn.startsWith("CMP") || mn.startsWith("TEST") || mn.startsWith("CALL") || mn.startsWith("LEA") || mn.startsWith("PUSH") || mn.startsWith("POP") || mn.startsWith("MOVZX") || mn.startsWith("MOVSX")) continue;
            if (ins.getNumOperands() < 2) continue;
            Scalar sc = ins.getScalar(0);
            if (sc == null) continue;
            long v = sc.getValue();
            if (inWin(v)) {
                String rep = ins.toString();
                if (rep.contains("ptr [")) println(ins.getAddress() + "  " + rep);
            }
        }
    }
}
