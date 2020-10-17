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
# r1 : libpcap in Motorola format                                             #
#                                                                             #
#-----------------------------------------------------------------------------#

from os import path
from time import time
import sys

def main() :
 print("\"{}\" - copy selected frames from a file in libpcap format".format(path.basename(sys.argv[0])), file = sys.stderr)
 if len(sys.argv) != 4 :
  print("Syntax:\n {} <infile> <listfile> <outfile>".format(path.basename(sys.argv[0])), file = sys.stderr)
  sys.exit(64)
 eoin = False
 try :
  infile = open(sys.argv[1], "rb")
 except :
  print("Error: Infile \"{}\" not found".format(sys.argv[1]), file = sys.stderr)
  eoin = True
 try :
  lsfile = open(sys.argv[2], "rt")
 except :
  print("Error: Listfile \"{}\" not found".format(sys.argv[2]), file = sys.stderr)
  eoin = True
 if eoin == False :
  try :
   oufile = open(sys.argv[3], "wb")
  except :
   print("Error: Outfile \"{}\" not created".format(sys.argv[3]), file = sys.stderr)
   eoin = True
 if eoin == True :
  if "infile" in locals() :
   infile.close()
  if "lsfile" in locals() :
   lsfile.close()
  sys.exit(65)
 tmstp0 = int(time())
 tmstp1 = tmstp0
 lslnnr = 0
 olfrnr = 0
 while eoin == False :
  nufrnr = lsfile.readline()
  if bool(nufrnr) == False :
   if tmstp0 != tmstp1 :
    print("", file = sys.stderr)
   print("End of listfile reached at L#{}/F#{}".format(lslnnr, olfrnr), file = sys.stderr)
   eoin = True
   break
  else :
   lslnnr += 1
  try :
   nufrnr = int(nufrnr)
   if nufrnr >= 1 :
    if olfrnr == 0 :
     print("Processing infile \"{}\"...".format(sys.argv[1]), file = sys.stderr)
     olfrnr = nufrnr
     frnr = 0
     frbuff = infile.read(24)
     if frbuff[0:4] == b"\xa1\xb2\xc3\xd4" or frbuff[0:4] == b"\xd4\xc3\xb2\xa1" or frbuff[0:4] == b"\x0a\x0d\x0d\x0a" :
      print("Infile \"{}\" format {}".format(sys.argv[1], frbuff[0:4]), file = sys.stderr)
      infrmt = frbuff[0:1]
     else :
      print("Error: Infile \"{}\" format unknown".format(sys.argv[1]), file = sys.stderr)
     oufile.write(frbuff)
    elif nufrnr <= olfrnr :
     if tmstp0 != tmstp1 :
      print("", file = sys.stderr)
     print("Warning: Listfile \"{}\" line#{} next frame {} < previous frame {}, skipping...".format(sys.argv[2], lslnnr, nufrnr, olfrnr), file = sys.stderr)
     continue
   else :
    if tmstp0 != tmstp1 :
     print("", file = sys.stderr)
    print("Warning: Listfile \"{}\" line#{} next frame {} skipping...".format(sys.argv[2], lslnnr, nufrnr), file = sys.stderr)
   tmstp2 = int(time())
   if tmstp1 != tmstp2 :
    print("\rin F#{} list L#{}F#{}, {} s".format(frnr, lslnnr, nufrnr, tmstp2 - tmstp0), end = ' ', file = sys.stderr)
    tmstp1 = tmstp2
  except :
   if tmstp0 != tmstp1 :
    print("", file = sys.stderr)
   print("Warning: Listfile \"{}\" line #{} \"{}\" not a valid number".format(sys.argv[2], lslnnr, nufrnr.rstrip("\n")), file = sys.stderr)
   continue
  while frnr < nufrnr :
   frbuff = infile.read(16)
   if len(frbuff) < 16 :
    eoin = True
    if tmstp0 != tmstp1 :
     print("", file = sys.stderr)
    print("End of infile reached at F#{}, before listfile F#{}".format(frnr, nufrnr), file = sys.stderr)
    break
   frnr += 1
   tmstp2 = int(time())
   if tmstp1 != tmstp2 :
    print("\rin F#{} list L#{}/F#{}, {} s".format(frnr, lslnnr, nufrnr, tmstp2 - tmstp0), end = ' ', file = sys.stderr)
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
 infile.close()
 lsfile.close()
 oufile.close()
 print("Processing done", file = sys.stderr)

if __name__ == "__main__" : main()
