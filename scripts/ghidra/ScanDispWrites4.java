// ScanDispWrites4.java — 쓰기 명령 중 dest 오퍼랜드 객체에 Scalar {0xf5,0xf6,0x1c0,0x1c4} 포함 시 출력 (getOpObjects 방식)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

public class ScanDispWrites4 extends GhidraScript {
    static final long[] offs = {0xf5L, 0xf6L, 0x1c0L, 0x1c4L};
    static boolean inWin(long v) { return (v >= 0xe0 && v <= 0x110) || (v >= 0x1a8 && v <= 0x1e0); }
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
            Object[] objs = ins.getOpObjects(0);
            if (objs == null) continue;
            String rep = null;
            for (Object o : objs) {
                if (!(o instanceof Scalar)) continue;
                long v = ((Scalar) o).getValue();
                for (long t : offs) {
                    if (v == t || inWin(v)) {
                        if (rep == null) rep = ins.getAddress() + "  " + ins.toString();
                        println(rep);
                        break;
                    }
                }
                if (rep != null) break;
            }
        }
    }
}
