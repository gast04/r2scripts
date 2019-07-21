from termcolor import colored

def print_syscall(disasm, rip, regs):
  print("{}: ".format(hex(rip)) +  colored(disasm, "red") + "({})".format(hex(regs['rax'])) + " Stop (Y/N)")

def print_call(disasm, rip):
  print("{}: ".format(hex(rip)) +  colored(disasm, "blue") + " Stop (Y/N)")
