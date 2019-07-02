import re


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

def getRegValue(reg, regs):
  # if it end with "d" remove it
  # Example: r12d
  if reg.endswith("d"):
    return regs[reg[:-1]]
  return regs[reg]

def is_number(m):
  if m.isdigit():
    return int(m), False
  try:
    val = int(m,16)
    return val, False
  except:
    return -1, True

def identifyRW(disasm, imgData):
  inst = disasm.split(" ")[0]
  tmp = disasm.split(",")
  if "[" in tmp[0]:
    imgData[-1][2] = "read/write"
    if inst == "cmp":
      imgData[-1][2] = "read"
    if inst == "mov":
      imgData[-1][2] = "write"
  elif "[" in tmp[1]:
    imgData[-1][2] = "read"    
  #print(imgData[-1][2])

def getDerefAddr(regs, disasm, imgData):
  #print(disasm)

  if "*" in disasm:
    print("cannot disasm *")
    return None, None

  identifyRW(disasm, imgData)

  raw = re.search("\[.*\]", disasm).group()
  deref = raw[1:-1] # return deref operands
  parts = deref.split(" ")

  args = []
  for p in parts:

    # check for register
    if p[0] == 'r' or p[0] == 'e': # register check
      args.append(getRegValue(p, regs))

    #  check for constant
    val, error = is_number(p)
    if error == False:
      args.append(val)

    # operand check
    if p == "-":
      operand = "-"
    elif p == "+":
      operand = "+" 

  if operand == "-":
    deref_addr = args[0] - args[1]
  elif operand == "+":
    deref_addr = args[0] + args[1]
  else:
    deref_addr = val

  imgData[-1][1] = deref_addr
  return raw, deref_addr
