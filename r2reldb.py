import sys,r2pipe

r2p = r2pipe.open()

if len(sys.argv) != 2:
    print("parameter missmatch")
    sys.exit()

offset = int(sys.argv[1], 16)

# get binary name
binfo = r2p.cmdj("iIj")
baddr = binfo['baddr']

db_addr = baddr + offset

# change search space to stack
r2p.cmd("db {}".format(hex(db_addr)))

