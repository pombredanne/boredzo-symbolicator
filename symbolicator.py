#!/usr/bin/python

import subprocess
import fileinput
import sys
import re
import optparse

parser = optparse.OptionParser(usage="%prog [options] [files]", description="Reads one or more crash logs from named files or standard input, symbolicates them, and writes them to standard output.")
opts, args = parser.parse_args()

def architecture_for_code_type(code_type):
	arch_code_type_name = code_type.split()[0]
	code_types_to_architectures = {
		'X86': 'i386',
		'PPC': 'ppc',
	}
	return code_types_to_architectures[arch_code_type_name]

recognized_versions = [
	6,
]

def reformat_UUID(UUID):
	"Takes a plain-hex-number UUID, uppercases it, and inserts hyphens."
	UUID = UUID.upper()
	if len(UUID) == 36:
		# Already hyphenated.
		pass
	else:
		UUID = '-'.join([UUID[0:8], UUID[8:12], UUID[12:16], UUID[16:20], UUID[20:]])
	return UUID

def find_dSYM_by_UUID(UUID):
	mdfind = subprocess.Popen(['mdfind', 'com_apple_xcode_dsym_uuids = ' + reformat_UUID(UUID)], stdout=subprocess.PIPE)
	try:
		dSYM_path = iter(mdfind.stdout).next()[:-1] # Strip \n
	except StopIteration:
		dSYM_path = None
	mdfind.wait()
	return dSYM_path
def find_dSYM_by_bundle_ID(bundle_ID):
	return find_dSYM_by_UUID(binary_images[bundle_ID])

def parse_binary_image_line(line):
	elements = iter(line.split())

	start_address = elements.next()
	elements.next() # Hyphen-minus
	end_address = elements.next()
	bundle_ID = elements.next()
	short_version = elements.next()
	bundle_version = elements.next()
	UUID_in_brackets = elements.next()

	UUID = UUID_in_brackets.strip('<>')
	# The main(?) executable has plus sign before its bundle ID. Strip this off.
	bundle_ID = bundle_ID.lstrip('+')

	return (bundle_ID, UUID)

def look_up_address_by_bundle_ID(bundle_ID, address):
	dSYM_path = find_dSYM_by_bundle_ID(bundle_ID)
	if dSYM_path:
		dwarfdump = subprocess.Popen(['dwarfdump', '--lookup', address, dSYM_path], stdout=subprocess.PIPE)

		we_care = False
		tag_compile_unit = False
		tag_subprogram = False
		filename = function = '(unknown)'
		line_number = 0
		for line in dwarfdump.stdout:
			line = line.strip()
			if line.startswith('File: '):
				if ('(architecture %s)' % (architecture,)) in line:
					we_care = True
					tag_compile_unit = False
					tag_subprogram = False
				else:
					we_care = False
			elif we_care:
				if 'TAG_compile_unit' in line:
					tag_compile_unit = True
					tag_subprogram = False
				elif 'TAG_subprogram' in line:
					tag_compile_unit = False
					tag_subprogram = True
				elif line.startswith('AT_name('):
					name = ' '.join(line.split()[1:-1]).strip('"')
					if tag_compile_unit:
						filename = name
					elif tag_subprogram:
						function = name
				elif line.startswith('Line table file: '):
					match = re.search("'[^']+'", line)
					if match:
						filename = match.group(0).strip("'")
					# The line number is the first decimal number after the filename.
					match = re.search('[0-9]+', line[match.end(0):])
					if match:
						line_number = int(match.group(0))
		else:
			dwarfdump.wait()

		return '%s (%s:%s)' % (function, filename, line_number)
	else:
		return None

def symbolicate_backtrace_line(line):
	match = re.match('[0-9]+\s+([-_a-zA-Z\./]+)\s+(0x[0-9A-Fa-f]+)\s+', line)
	if not match:
		return line

	bundle_ID = match.group(1)
	address = match.group(2)

	function_info = look_up_address_by_bundle_ID(bundle_ID, address)
	if function_info is None:
		return line
	else:
		return line[:match.end(0)] + function_info
		return line.replace(address, new_address)

work = False
architecture = None
is_in_backtrace = False
is_in_thread_state = False
is_in_binary_images = False
backtrace_lines = []
thread_state_lines = []
binary_image_lines = []
binary_images = {} # Keys: bundle IDs; values: UUIDs

for line in fileinput.input(args):
	line = line.strip()
	if line.startswith('Process:'):
		# New crash
		work = True
		is_in_backtrace = is_in_thread_state = is_in_binary_images = False
	elif not work:
		continue
	elif line.startswith('Report Version:'):
		version = int(line[len('Report Version:'):])
		if version not in recognized_versions:
			work = False
	elif line.startswith('Code Type:'):
		architecture = architecture_for_code_type(line[len('Code Type:'):].strip())
	elif line.startswith('Thread ') and line.endswith(' Crashed:'):
		is_in_backtrace = True
	elif is_in_backtrace and ('Thread State' in line):
		is_in_backtrace = False
		is_in_thread_state = True
		thread_state_lines.append(line)
	elif line == 'Binary Images:':
		is_in_thread_state = False
		is_in_binary_images = True
	elif is_in_thread_state:
		thread_state_lines.append(line)
	elif is_in_backtrace:
		backtrace_lines.append(line)
	elif not is_in_binary_images:
		# We haven't gotten to backtrace or binary images yet. Pass this line through.
		print line
	elif is_in_binary_images:
		if line.strip():
			binary_image_lines.append(line)
			bundle_ID, UUID = parse_binary_image_line(line)
			binary_images[bundle_ID] = UUID
		else:
			# End of crash
			for line in backtrace_lines:
				print symbolicate_backtrace_line(line)
			for line in thread_state_lines:
				print line
			for line in binary_image_lines:
				print line
