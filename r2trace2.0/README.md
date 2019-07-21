# r2_tracer 2.1
basically strace functionality for r2, with some handy features for quick 
analysis of binaries\
Reverse Engineering can be a hard task, especially on big binaries, this tool makes
it a bit easier, we can focus our analysis only on the executed parts

# Features
* get a full instruction trace of all executed instructions
* specify a trace range
* dump memory where registers are pointing to
* stop at every function call or syscall and inspect memory (only functions so far)
* generate a bitmap image of read/write accesses (working draft)

##### Bitmap
This can be really useful to detect patterns in the binary, for example cryptographic patterns
which acces memory always the same way.\
It's a time/access image where the y-acis is the timeand x-axis are the memory adresses 
(here we have to separate Heap and Stack, this is a open TODO)\
see bitmap files for an exmaple\
Legend: read = Red, write = Green, read & write = yellow

# Startup
add this to .radare2rc file:\
`(t2, #!pipe python <PathToRepository>/r2scripts/r2trace2.0/r2trace.py)`
and start r2 with:\
`r2 -d -c '.(t2)' <binary>`

if you stop the execution at a certain point, you can continue the tracing
by calling `.(t2)` again

# Requirements
r2pipe, termcolor\
can be installed by pip

# Future Work
* generate a Control Flow Graph out of the Trace
