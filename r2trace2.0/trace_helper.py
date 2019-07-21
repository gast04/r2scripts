
from util import *

def write_trace(insttrace, msg, regs, operand, data):
  insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}, {}: {}\n".format(
    tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi']), operand, tohex(data[0]) ))

def write_trace_simple(insttrace, msg, regs):
  insttrace.write(msg + "\tRAX: {}, RBX: {}, RCX: {}, RDX: {}, RDI: {}, RSI:{}\n".format(
    tohex(regs['rax']), tohex(regs['rbx']), tohex(regs['rcx']), tohex(regs['rdx']), tohex(regs['rdi']), tohex(regs['rsi'])))

