// ScanDispWrites.java — .text 전체에서 [reg+disp] 형태 메모리 쓰기 중 disp가 지정 값인 명령 출력
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

public class ScanDispWrites extends GhidraScript {
    static final long[] offs = {0x70L, 0x74L, 0x78L, 0x7cL};
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
            if (!(mn.equals("MOV") || mn.equals("MOVDQA") || mn.equals("MOVDQU") || mn.equals("MOVUPS") || mn.equals("MOVAPS"))) continue;
            if (ins.getNumOperands() < 2) continue;
            // 목적지 오퍼랜드(0)의 스칼라 확인
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
