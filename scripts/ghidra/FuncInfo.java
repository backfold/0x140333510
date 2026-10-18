// FuncInfo.java — 주어진 주소를 포함하는 함수의 시작/끝 주소 출력
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class FuncInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = getFunctionContaining(addr);
            if (f == null) println(a + " : (함수 아님)");
            else println(a + " : " + f.getName() + " " + f.getEntryPoint() + " .. " + f.getBody().getMaxAddress() + " size=" + f.getBody().getNumAddresses());
        }
    }
}
