import r2pipe
import re

from util import *
from dump_helper import *
from imageHelp import *

# trace constants
'''
start_addr = 0x00401c05 
end_addr =   0x00403000
stop_addr =  0x00402072
'''
start_addr = 0x13370000
end_addr = 0x13370000 + 126960
stop_addr = 0x1337b6ff

r2p = r2pipe.open()
r2p.cmd("dcu main") # start at main function
#r2p.cmd("dcu 0x40974C")

insttrace = open("it_trace", "w+")
regdumps = open("reg_dump", "w+")
#enableRegDump()

# image data
imgdata = []
savename = "trace.bmp"

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

print("\n\nstart Tracing")
print("trace Region: {} - {}".format(hex(start_addr), hex(end_addr)))
print("\n")

execution_step = 0

## main loop
while True:
    
  # perform one step
  r2p.cmd("ds")
  regs = getRegs()
  rip = regs['rip']

  # specify code range, if needed
  if rip < start_addr or rip > end_addr:
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

  regDump(regdumps, rip, regs) # dump register pointers
  msg = "{}: {}".format( tohex(rip), disasm.ljust(24," ") )
  
  # print all dereferences
  if '[' in disasm:
    imgdata.append([execution_step, 0, ""])
    operand, deref = getDerefAddr(regs, disasm, imgdata)

    data = r2p.cmdj("pxwj {} @ {}".format(4, deref))
    insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}, {}: {}\n".format( 
      tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi']), operand, tohex(data[0]) ))
  else:
    insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}\n".format( 
      tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi'])))

  execution_step += 1
  if execution_step >= 1000:
    break

  # Stop Tracing at address
  if rip == stop_addr:
      print("Stopping")
      break

# create a bitmap of the trace
createImage(imgdata, savename)

# close dump files
insttrace.close()
regdumps.close()
