
undefined8 FUN_1402b2480(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  undefined8 *puVar1;
  
  puVar1 = operator_new(0x28);
  if (puVar1 != (undefined8 *)0x0) {
    *puVar1 = Lambda::Stream::vftable;
    *puVar1 = Lambda::BufferStream::vftable;
    *(undefined1 *)(puVar1 + 1) = 0;
    puVar1[2] = param_2;
    *(undefined4 *)(puVar1 + 3) = param_3;
    puVar1[4] = param_2;
    *(undefined4 *)((longlong)puVar1 + 0x1c) = 0;
  }
  FUN_1402b21d0(param_1,puVar1);
  return param_1;
}

