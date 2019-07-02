
reg_enable = False

def enableRegDump():
  reg_enable = True

# dump bytes a register is pointing to
def regDump(regdumps, addr, regs):

    if reg_enable == False:
      return

    regdumps.write("\n{}:\n".format(hex(addr)))
    
    regdumps.write("RAX: {}\n".format(hex(regs["rax"])))
    if regs["rax"] != 0:
        regdumps.write(getDump(regs["rax"]))

    regdumps.write("RBX: {}\n".format(tohex(regs["rbx"])))
    if regs["rbx"] != 0:
        regdumps.write(getDump(regs["rbx"]-24, 64))

    regdumps.write("RCX: {}\n".format(hex(regs["rcx"])))
    if regs["rcx"] != 0:
        regdumps.write(getDump(regs["rcx"]))

    regdumps.write("RDX: {}\n".format(hex(regs["rdx"])))
    if regs["rdx"] != 0:
        regdumps.write(getDump(regs["rdx"]))

    regdumps.write("RSI: {}\n".format(hex(regs["rsi"])))
    if regs["rsi"] != 0:
        regdumps.write(getDump(regs["rsi"]))

    regdumps.write("RDI: {}\n".format(hex(regs["rdi"])))
    if regs["rdi"] != 0:
        regdumps.write(getDump(regs["rdi"]))
