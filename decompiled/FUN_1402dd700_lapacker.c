
undefined8 FUN_1402dd700(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  
  lVar1 = param_2 + 0xc0;
  if (0xf < *(ulonglong *)(param_2 + 0xd8)) {
    lVar1 = *(longlong *)(param_2 + 0xc0);
  }
  FUN_1400bfea0("PKG File open Error ( %ls : %s )",*(undefined8 *)(param_2 + 0x90),lVar1);
  if (DAT_1403e3aa8 != '\0') {
    FUN_1400b1740(param_2 + 0x30,"game\\sa_text_00000.pkg");
    FUN_1400b1740(param_2 + 0x30,"game\\sa_scripts_00000.pkg");
    FUN_1400b1740(param_2 + 0x30,"game\\sa_charactersc_00000.pkg");
    DAT_1403e3aa8 = '\0';
  }
  return 0;
}


