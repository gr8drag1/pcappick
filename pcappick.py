#!/usr/bin/env python3

#-----------------------------------------------------------------------------#
# Copyright 2020 Packet Detectives, Vadim Zakharine and contributors.         #
# License GPLv2+: GNU GPL version 2 or later                                  #
# <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>                     #
# This is free software; see the source for copying conditions. There is NO   #
# warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. #
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# PDETIPv4 Utility for detecting IPv4 packet headers in dump files            #
#                                                                             #
# r1 : Initial release, libpcap in Intel format                               #
# r2 : libpcap in Motorola format                                             #
# r3 : End of input flag no longer required                                   #
#                                                                             #
#-----------------------------------------------------------------------------#

from os import path
from time import time
import sys

def main() :
 print("\"{}\" - copy selected frames from a file in libpcap format".format(path.basename(sys.argv[0])), file = sys.stderr)
 if len(sys.argv) != 4 :
  print("Syntax:\n {} <infile> <list> <outfile>".format(path.basename(sys.argv[0])), file = sys.stderr)
  sys.exit(64)
 try :
  infile = open(sys.argv[1], "rb")
 except FileNotFoundError :
  print("Error: Infile \"{}\" not found".format(sys.argv[1]), file = sys.stderr)
  sys.exit(66)
 try :
  lsfile = open(sys.argv[2], "rt")
 except FileNotFoundError :
  print("Error: List \"{}\" not found".format(sys.argv[2]), file = sys.stderr)
  infile.close()
  sys.exit(66)

 tmstp0 = int(time()) # reference
 tmstp1 = tmstp0      # last current
 tmstp2 = tmstp0      # current
 olfrnr = 0
 lslnnr = 0

 for nufrnr in lsfile :
  lslnnr += 1
  try :
   nufrnr = int(nufrnr)
  except :
   print("\nWarning: List \"{}\" line #{} \"{}\" not a valid number, skipping...".format(sys.argv[2], lslnnr, nufrnr.rstrip("\n")), file = sys.stderr)
   continue
  if nufrnr >= 1 :
   if olfrnr == 0 :
    print("Processing infile \"{}\"...".format(sys.argv[1]), file = sys.stderr)
    olfrnr = nufrnr
    frnr = 0
    frbuff = infile.read(24)
    if len(frbuff) == 24 :
     if frbuff[0:4] == b"\xa1\xb2\xc3\xd4" or frbuff[0:4] == b"\xd4\xc3\xb2\xa1" or frbuff[0:4] == b"\x0a\x0d\x0d\x0a" :
      print("Infile \"{}\" format {}".format(sys.argv[1], frbuff[0:4]), file = sys.stderr)
      infrmt = frbuff[0:1]
     else :
      print("Error: Infile \"{}\" format unknown".format(sys.argv[1]), file = sys.stderr)
      infile.close()
      lsfile.close()
      sys.exit(65)
     try :
      oufile = open(sys.argv[3], "wb")
     except :
      print("Error: Outfile \"{}\" creation failure".format(sys.argv[3]), file = sys.stderr)
      infile.close()
      lsfile.close()
      sys.exit(73)
     oufile.write(frbuff)
    else :
     print("Error: Infile \"{}\" too short".format(sys.argv[1]), file = sys.stderr)
     infile.close()
     lsfile.close()
     sys.exit(65)
   elif nufrnr <= olfrnr :
    print("Warning: List \"{}\" line#{} next frame {} < previous frame {}, skipping...".format(sys.argv[2], lslnnr, nufrnr, olfrnr), file = sys.stderr)
    continue
  else :
   if tmstp2 != tmstp0 :
    if tmstp2 == tmstp1 :
     # Before the warning message add a new line in case the progress indicator was printed earlier
     print("", file = sys.stderr)
     tmstp2 = tmstp1 - 1
   print("Warning: List \"{}\" line#{} next frame {} skipping...".format(sys.argv[2], lslnnr, nufrnr), file = sys.stderr)
   continue

  while frnr < nufrnr :
   frbuff = infile.read(16)
   if len(frbuff) < 16 :
    print("\nEnd of infile reached at F#{}, before list F#{}".format(frnr, nufrnr), file = sys.stderr)
    infile.close()
    lsfile.close()
    oufile.close()
    sys.exit(0)
   frnr += 1
   tmstp2 = int(time())
   if tmstp1 != tmstp2 :
    print("\rF#{} list L#{}/F#{}, {} s".format(frnr, lslnnr, nufrnr, tmstp2 - tmstp0), end = ' ', file = sys.stderr)
    tmstp1 = tmstp2
   if frnr < nufrnr :
    # Skip the frame
    # print("Frame {} -> skip {} B".format(frnr, ((int(frbuff[11]) * 256 + int(frbuff[10])) * 256 + int(frbuff[9])) * 256 + int(frbuff[8])), file = sys.stderr)
    if infrmt == b'\xd4' :
     infile.seek(((int(frbuff[11]) * 256 + int(frbuff[10])) * 256 + int(frbuff[9])) * 256 + int(frbuff[8]), 1)
    elif infrmt == b'\xa1' :
     infile.seek(((int(frbuff[8]) * 256 + int(frbuff[9])) * 256 + int(frbuff[10])) * 256 + int(frbuff[11]), 1)
    else :
     print("Infile format {} not supported".format(infrmt), file = sys.stderr)
     sys.exit(65)
    frbuff = b"".join([frbuff[0:8], b'\x00\x00\x00\x00', frbuff[12:16]])
    oufile.write(frbuff)
   elif frnr == nufrnr :
    # Copy the frame
    # print("Frame {} -> copy {} B".format(frnr, ((int(frbuff[11]) * 256 + int(frbuff[10])) * 256 + int(frbuff[9])) * 256 + int(frbuff[8])), file = sys.stderr)
    oufile.write(frbuff)
    if infrmt == b'\xd4' :
     frbuff = infile.read(((int(frbuff[11]) * 256 + int(frbuff[10])) * 256 + int(frbuff[9])) * 256 + int(frbuff[8]))
    elif infrmt == b'\xa1' :
     frbuff = infile.read(((int(frbuff[8]) * 256 + int(frbuff[9])) * 256 + int(frbuff[10])) * 256 + int(frbuff[11]))
    else :
     print("Infile format {} not supported".format(infrmt), file = sys.stderr)
     sys.exit(65)
    oufile.write(frbuff)
    olfrnr = nufrnr

 print("\nEnd of list reached at L#{}/F#{}".format(lslnnr, olfrnr), file = sys.stderr)
 infile.close()
 lsfile.close()
 oufile.close()
 print("Processing done", file = sys.stderr)

if __name__ == "__main__" : main()
