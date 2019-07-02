from PIL import Image

def createImage(data, savename):

  print(data)

  # take care of stack and heap data, (easy eliminate)
  delimiter = 0x7ff000000000
  delimiter = 0x13370000
  newdata = list(filter(lambda x: x[1]>delimiter and x[1]<0x133afd28, data))

  # take the max instruction count (maybe not all included, register operations)
  y_size = max([x[0] for x in newdata])
  ma = max([x[1] for x in newdata])
  mi = min([x[1] for x in newdata])
  print("ranges: {}/{}".format(ma-mi, y_size))

  img = Image.new("RGB", ((ma-mi)+1, y_size+1), "black")
  pixels = img.load()

  # x(time), y(address), "read/write"
  for d in newdata:
    if d[2] == "read":
      pixels[d[1]-mi, d[0]] = (255,0,0)
    elif d[2] == "write":
      pixels[d[1]-mi, d[0]] = (0,255,0)
    elif d[2] == "read/write":
      pixels[d[1]-mi, d[0]] = (255,255,0)  

  img.show()
  img.save(savename)
