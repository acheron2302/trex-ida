Instruction { addr: 0xffffffffffffffff, op: FunctionStart, output: Unused, inputs: [ILA(1), Unused], indtgts: [] }
Instruction { addr: 0x140001000, op: Nop, output: Unused, inputs: [Unused, Unused], indtgts: [] }
Instruction { addr: 0x140001003, op: IntEqual, output: Varnode{as=3, off=0, sz=1}, inputs: [Varnode{as=0, off=1, sz=8}, $0u8], indtgts: [] }
Instruction { addr: 0x140001003, op: Cbranch, output: Unused, inputs: [MCA(0x140001013), Varnode{as=3, off=0, sz=1}], indtgts: [] }
Instruction { addr: 0x140001005, op: IntAdd, output: Varnode{as=3, off=2, sz=8}, inputs: [Varnode{as=0, off=1, sz=8}, $8u8], indtgts: [] }
Instruction { addr: 0x140001005, op: Load, output: Varnode{as=3, off=1, sz=8}, inputs: [Deref@1,sz=8{as=3, off=2}, Unused], indtgts: [] }
Instruction { addr: 0x140001005, op: IntEqual, output: Varnode{as=3, off=3, sz=1}, inputs: [Varnode{as=3, off=1, sz=8}, $0u8], indtgts: [] }
Instruction { addr: 0x140001005, op: Cbranch, output: Unused, inputs: [MCA(0x140001013), Varnode{as=3, off=3, sz=1}], indtgts: [] }
Instruction { addr: 0x14000100e, op: IntAdd, output: Varnode{as=3, off=4, sz=8}, inputs: [Varnode{as=0, off=1, sz=8}, $8u8], indtgts: [] }
Instruction { addr: 0x14000100e, op: Load, output: Varnode{as=0, off=1, sz=8}, inputs: [Deref@1,sz=8{as=3, off=4}, Unused], indtgts: [] }
Instruction { addr: 0x140001011, op: Branch, output: Unused, inputs: [MCA(0x140001005), Unused], indtgts: [] }
Instruction { addr: 0x140001013, op: Copy, output: Varnode{as=0, off=0, sz=8}, inputs: [Varnode{as=0, off=1, sz=8}, Unused], indtgts: [] }
Instruction { addr: 0xffffffffffffffff, op: FunctionEnd, output: Unused, inputs: [Unused, Unused], indtgts: [] }
