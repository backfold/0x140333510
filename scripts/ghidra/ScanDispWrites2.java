// ScanDispWrites2.java — .text 전체에서 [reg+disp] 쓰기 중 disp ∈ {0xf5,0xf6,0x1c0,0x1c4} (매니저 설정 필드) 출력
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

public class ScanDispWrites2 extends GhidraScript {
    static final long[] offs = {0xf5L, 0xf6L, 0x1c0L, 0x1c4L};
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
            for (long o : offs) {
                if (v == o) {
                    String rep = ins.toString();
                    if (rep.contains("ptr [")) println(ins.getAddress() + "  " + rep);
                    break;
                }
            }
        }
    }
}
