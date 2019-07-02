# r2_tracer 2.0

same as r2_tracer but it generates a image out of the 
instruction which use memory, to generate a 
time/acces image to detect patters in the behaviour

it's a prototype, but works well for simple programs
see the bitmap files

y-axis is the time (executed instruction)
x-axis are the memory addresses (we need to split between heap and stack
otherwise the image gets too big, this is a TODO)

