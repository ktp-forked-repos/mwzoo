#!/usr/bin/python
# vim:ts=2:sw=2:et

import pefile
import sys

pe =  pefile.PE(sys.argv[1], fast_load=True)

info = {}

#logic for the pesections
info["sections"] = {}
for section in pe.sections:
  info["sections"][section.Name] = {}
  info["sections"][section.Name]["VirtualAddress"] = hex(section.VirtualAddress)
  info["sections"][section.Name]["Misc_VirtualSize"] = hex(section.Misc_VirtualSize)
  info["sections"][section.Name]["SizeOfRawData"] = section.SizeOfRawData
