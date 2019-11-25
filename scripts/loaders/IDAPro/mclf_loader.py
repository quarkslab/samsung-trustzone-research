'''
* This program is free software ; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation ; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY ; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with the program ; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* @file mclf_loader.py
* @brief Mobicore trustlet and drive binary loader for IDA
* @author Gassan Idriss <ghassani@gmail.com>
'''
import struct
import sys
import idaapi
import idc
import ida_bytes
import ida_idp
import ida_name
import ida_segregs

MCLF_HEADER_MAGIC 		= b"MCLF"
MCLF_HEADER_SIZE_V1 	= 72
MCLF_HEADER_SIZE_V2 	= 76
MCLF_HEADER_SIZE_V23 	= 96
MCLF_TEXT_INFO_OFFSET 	= 128
MCLF_TEXT_INFO_SIZE 	= 36
MCLF_HEADER_SIZE 		= MCLF_TEXT_INFO_OFFSET + MCLF_TEXT_INFO_SIZE
tlApiLibEntry           = 0x108C

def decode(s):
    """Decodes UTF-8 bytes into a unicode string."""
    if isinstance(s, str):
        return s
    return s.decode("utf-8")

def accept_file(f, filename):
	retval = 0
	if filename == 0 or type(filename) == str:
		f.seek(0)
		magic = f.read(4)
		versionMinor = struct.unpack("<h", f.read(2))[0]
		versionMajor = struct.unpack("<h", f.read(2))[0]
		if magic == MCLF_HEADER_MAGIC and versionMajor > 1 and versionMajor < 3:
			retval = "%s v%d.%d executable for ARM" % (decode(magic), versionMajor, versionMinor)
	return retval

def load_file(f, neflags, format):
	f.seek(0)
	
	magic 		 	= f.read(4)
	version 	 	= struct.unpack("<I", f.read(4))[0]
	flags 		 	= struct.unpack("<I", f.read(4))[0]
	memType 	 	= struct.unpack("<I", f.read(4))[0]
	serviceType  	= struct.unpack("<I", f.read(4))[0]
	numInstances 	= struct.unpack("<I", f.read(4))[0]
	uuid 		 	= struct.unpack("<IIII", f.read(16))
	driverId 	 	= struct.unpack("<I", f.read(4))[0]
	numThreads 	 	= struct.unpack("<I", f.read(4))[0]
	textVA  	 	= struct.unpack("<I", f.read(4))[0]
	textLen 	 	= struct.unpack("<I", f.read(4))[0]
	dataVA  	 	= struct.unpack("<I", f.read(4))[0]
	dataLen 	 	= struct.unpack("<I", f.read(4))[0]
	bssLen 	 	 	= struct.unpack("<I", f.read(4))[0]
	entry 	 	 	= struct.unpack("<I", f.read(4))[0]

	f.seek(MCLF_TEXT_INFO_OFFSET)
	
	idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER_NON_FATAL)

	# Set VA for .text and add the segment
	f.file2base(0, textVA, textVA + textLen, True)
	idaapi.add_segm(0, textVA, textVA + textLen, ".text", "CODE")

	# Set VA for .data and add the segment
	f.file2base(textLen, dataVA, dataVA + dataLen, True)
	idaapi.add_segm(0, dataVA, dataVA + dataLen, ".data", "DATA")
	
	# Add BSS segment after .text and .data
	idaapi.add_segm(0, dataVA + dataLen, dataVA + dataLen + bssLen, ".bss", "BSS")

	if entry % 4 == 1: 
		#Thumb address is always +1 to set the T bit
		idaapi.add_entry(entry-1, entry-1, "_entry", 1)
		idc.split_sreg_range(entry-1, "T", 0x1, ida_segregs.SR_user)
	else:
		idaapi.add_entry(entry, entry, "_entry", 1)
		idc.split_sreg_range(entry, "T", 0x0, ida_segregs.SR_user)

	ida_bytes.create_data(tlApiLibEntry, idaapi.FF_DWORD, 4, idaapi.BADADDR)
	idc.set_name(tlApiLibEntry, "tlApiLibEntry", ida_name.SN_CHECK)
	return 1
