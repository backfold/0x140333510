import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

public class DisasmRange extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		for (int a = 0; a + 1 < args.length; a += 2) {
			long start = Long.parseUnsignedLong(args[a].replaceFirst("^0x", ""), 16);
			long end = Long.parseUnsignedLong(args[a + 1].replaceFirst("^0x", ""), 16);
			Address s = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(start);
			Address e = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(end);
			disassemble(s);
			Listing l = currentProgram.getListing();
			Instruction i = l.getInstructionAt(s);
			if (i == null) {
				println("== " + s + " .. " + e + " : no instruction at start ==");
				continue;
			}
			println("== " + s + " .. " + e + " ==");
			while (i != null && i.getAddress().compareTo(e) < 0) {
				StringBuilder b = new StringBuilder();
				for (byte x : i.getBytes()) b.append(String.format("%02x ", x));
				for (int p = b.length(); p < 30; p++) b.append(' ');
				println(i.getAddress() + "  " + b + i.toString());
				i = i.getNext();
			}
		}
	}
}
