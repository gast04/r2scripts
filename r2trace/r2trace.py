import r2pipe
import re

'''
run with: r2 -r profile.rr2 -c '.(exp)' -A -d <program>

# pipe program output to extra shell to manage IO
# or with pwntools...

profile.rr2
´´´
#!/usr/bin/rarun2
stdio=/dev/pts/2
´´´
'''

# trace constants
start_addr = 0x400000 
end_addr =   0x565918

r2p = r2pipe.open()
#r2p.cmd("dcu main") # start at main function
r2p.cmd("dcu 0x40974C")

insttrace = open("it_trace", "w+")
regdumps = open("reg_dump", "w+")

def tohex(val, nbits=32):
  return hex((val + (1 << nbits)) % (1 << nbits))

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % x for x in chars])
        printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%-*s  %s\n" % (length*3, hex, printable))
    return ''.join(lines)

def getRegs():
    return r2p.cmdj("drj")

# get disassembly of one instruction
def getDisasm(addr):
    p = r2p.cmdj("pdj 1 @ {}".format(addr))[0]
    if p['type'] == "invalid":
        return 'invalid'
    return p['disasm']

def getDump(addr, size = 32):
    hexbytes = r2p.cmdj("pxj {} @ {}".format(size,addr))
    return hexdump(hexbytes)

# dump bytes a register is pointing to
def regDump(addr, regs):
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

def getDerefAddr(regs, disasm):
  #print(disasm)
  raw = re.search("\[.*\]", disasm).group()
  deref = raw[1:-1] # return deref operands
  parts = deref.split(" ")

  deref_addr = 0
  if parts[0][0] == 'r' or parts[0][0] == 'e': # register check
    deref_addr = regs[parts[0]]

  if len(parts) == 1:
    return raw, deref_addr

  # if second part looks like rsi*2
  mulfactor = 1
  if "*" in parts[2]:
    mulfactor = int(parts[2].split("*")[1])
    secpart = parts[2].split("*")[0]
  else:
    secpart = parts[2]

  #print("secpart: {}, mulfactor: {}". format(secpart, mulfactor))
  # if more parts:[r12d + 0x3c] or [rbp + rcx]
  if secpart[0] == 'r' or secpart[0] == 'e': # [rbp + rcx] case
    tmp = regs[secpart]
  else:   # [rbx - constant] case 
    tmp = int(secpart,16)

  tmp *= mulfactor

  # middle part is always operand Plus or Minus
  if parts[1] == '+':
    deref_addr += tmp
  elif parts[1] == '-':
    deref_addr -= tmp

  return raw, deref_addr

###################################################################
# TODO: ignore standard functions, and generalize tracer more
# fetch library addresses and avoid there execution
# using: dmj and parse all executeable regions
###################################################################

print("\n\n start Tracing")
print("trace Region: {} - {}".format(hex(start_addr), hex(end_addr)))
print("\n")

## main loop
while True:
    
    # perform one step
    r2p.cmd("ds")
    regs = getRegs()
    rip = regs['rip']

    # specify code range, if needed
    if rip < start_addr and rip > end_addr:
        continue

    # get disasm of current rip
    disasm = getDisasm(rip)
    if disasm == "invalid":
        # should never happen
        print("Invalid instruction at: {}".format(hex(rip)))
        continue
    elif disasm == "int3":
        # ignore debug traps
        r2p.cmd("dr rip = {}".format(rip+1))
        rip = rip+1
        print("skip int3 at:{}".format(hex(rip)))
        disasm = getDisasm(rip)
    elif disasm == "nop":
        # ignore nops
        continue

    regDump(rip, regs) # dump register pointers
    msg = "{}: {}".format( tohex(rip), disasm.ljust(24," ") )
    
    # print all dereferences
    if '[' in disasm:
      operand, deref = getDerefAddr(regs, disasm)

      data = r2p.cmdj("pxwj {} @ {}".format(4, deref))
      insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}, {}: {}\n".format( 
        tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi']), operand, tohex(data[0]) ))
    else:
      insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}\n".format( 
        tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi'])))

    # Stop Tracing at address
    if rip == 0x4072BC:
        print("Valid Serial")
        break
    
    if rip == 0x407270:
        print("Invalid Serial")
        break


# close dump files
insttrace.close()
regdumps.close()
