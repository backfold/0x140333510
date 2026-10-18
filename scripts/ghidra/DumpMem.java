import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DumpMem extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long start = Long.parseUnsignedLong(args[0].replace("0x", ""), 16);
        long count = Long.parseUnsignedLong(args[1].replace("0x", ""), 16); // qword count
        Address a = currentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(start));
        for (int i = 0; i < count; i++) {
            long v = getLong(a.add(i * 8L)) & 0xFFFFFFFFFFFFFFFFL;
            println(String.format("0x%x: 0x%016x", start + i * 8L, v));
        }
    }
}
