import r2pipe, threading, time

from dump_helper import *
from imageHelp import *
from trace_helper import *
from inst_printing import *

# trace constants
'''
start_addr = 0x00401c05 
end_addr =   0x00403000
stop_addr =  0x00402072

start_addr = 0x13370000
end_addr = 0x13370000 + 126960
stop_addr = 0x1337b6ff
'''
start_addr = 0x400400
end_addr = 0x4025B5
stop_addr = end_addr


# Hyperparameters
GENERATE_IMAGE = True
ENABLE_REG_DUMP = False
PRINT_SYSCALLS = False
MAX_INSTRUCTIONS = 2000000

# open connection to r2 instance
r2p = r2pipe.open()
CONTINUATION = False

# check if it is a continuation
val = r2p.cmd("$r2trace.started?")
if val.strip() != "1":
  # first start
  #r2p.cmd("dcu main") # start at main function
  r2p.cmd("dcu 0x402580")
  r2p.cmd("$r2trace.started='1'") # mark execution as started
else:
  CONTINUATION = True

insttrace = open("it_trace", "a+")  # tracing is always enabled

if ENABLE_REG_DUMP:
  regdumps = open("reg_dump", "w+")
  enableRegDump(regdumps)
enableRegDump(None)

# Instruction Counting
inst_count_total = 0
inst_count_range = 0

# Image Data
imgdata = []
savename = "trace.bmp"

MAIN_LOOP = True
PAUSE_WAIT = True
PAUSE_INP = ""
def exit_thread():
  global MAIN_LOOP, PAUSE_WAIT, PAUSE_INP
  while True:
    ein = input().strip()  # waiting for any userinput
    if ein != "Y" and ein != "N" and ein != "y" and ein != "n":
      print("Tracing Stopped by User")
      MAIN_LOOP = False
      break
    else:
      PAUSE_INP = ein
      PAUSE_WAIT = False

def getRegs():
    return r2p.cmdj("drj")

# get disassembly of one instruction
def getDisasm(addr):
    p = r2p.cmdj("pdj 1 @ {}".format(addr))[0]
    if p['type'] == "invalid":
        return 'invalid'
    return p['disasm']

def printingWrapper(disasm, rip, regs):
  global PAUSE_WAIT, PAUSE_INP

  wait = False
  if "syscall" in disasm:
    print_syscall(disasm, rip, regs)
    wait = True
  elif "call" in disasm:
    print_call(disasm, rip)
    wait = True

  if wait:
    while PAUSE_WAIT:
      time.sleep(0.5)
    PAUSE_WAIT = True
    if PAUSE_INP == "Y" or PAUSE_INP == "y":
      PAUSE_INP = ""
      return True
  return False



if not CONTINUATION:
  print("\n\nstart Tracing")
  print("trace Region: {} - {}".format(hex(start_addr), hex(end_addr)))
  print("\n")

# start exit thread
exit_t = threading.Thread(target=exit_thread, args=())
exit_t.start()

## main loop
while MAIN_LOOP:
    
  # perform one step
  r2p.cmd("ds")
  regs = getRegs()
  rip = regs['rip']
  inst_count_total += 1

  # specify code range, if needed
  if rip < start_addr or rip > end_addr:
      print(hex(rip))
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
  elif disasm == "ud2":
    print("Invalid ud2 Instruction at {}, stop tracing".format(hex(rip)))
    break
  elif disasm == "nop":
      continue

  inst_count_range += 1
  regDump(rip, regs)  # dump register pointers
  msg = "{}: {}".format( tohex(rip), disasm.ljust(24, " ") )

  # pause on calls and syscalls
  if printingWrapper(disasm, rip, regs):
    break

  # print all dereferences
  if '[' in disasm:
    imgdata.append([inst_count_range, 0, ""])
    operand, deref = getDerefAddr(regs, disasm, imgdata)
    data = r2p.cmdj("pxwj {} @ {}".format(4, deref))
    write_trace(insttrace, msg, regs, operand, data)
  else:
    write_trace_simple(insttrace, msg, regs)

  if inst_count_range >= MAX_INSTRUCTIONS:
    break

  # Stop Tracing at address
  if rip == stop_addr:
      print("Stopping")
      break


# Print Instruction Counting Information
print("\n\nTraced Range: {} - {}".format(hex(start_addr), hex(end_addr)))
print("Instruction Counting:")
print("Total: {}".format(inst_count_total))
print("Range: {}".format(inst_count_range))

# create a bitmap of the trace
if GENERATE_IMAGE:
  createImage(imgdata, savename)

# close dump files
insttrace.close()
if ENABLE_REG_DUMP:
  regdumps.close()
