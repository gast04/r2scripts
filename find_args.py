
'''
	simple python-r2-script to find the command line 
	arguments of a binary
'''

import r2pipe

r2p = r2pipe.open()

# get binary name
binfo = r2p.cmdj("ij")
filename = binfo['core']['file'].split('/')[-1]

# save current search.in
search_in = r2p.cmd("e search.in")
#print("saved: {}".format(search_in))

# change search space to stack
r2p.cmd("e search.in=dbg.stack")

# search for filename (only use first finding)
res = r2p.cmdj("/j {}".format(filename))[0]
#print("found at: {}".format(hex(res['offset'])))

# save current seek
seek = r2p.cmd("s")

# parse command line arguments
args = []
r2p.cmd("s {}".format(res['offset']))

while True:
	arg = r2p.cmd("psz")
	#print("arg: {}".format(arg))
	addr = int(r2p.cmd("s"),16)
	leng = len(arg)+1

	if arg.startswith("LANG"):
		break
	
	r2p.cmd("s +{}".format(leng))
	args.append( (addr,arg) )
	
print("args:")
for entry in args:
	print("{}: {}".format(hex(entry[0]), entry[1]))

# restore search space and seek
r2p.cmd("e search.in={}".format(search_in))
r2p.cmd("s {}".format(seek))

