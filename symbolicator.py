#!/usr/bin/python

import subprocess
import fileinput
import sys
import os
import re
import optparse

def architecture_for_code_type(code_type):
	arch_code_type_name = code_type.split()[0]
	code_types_to_architectures = {
		'X86': 'i386',
		'X86-64': 'x86_64',
		'PPC': 'ppc',
		'ARM': 'arm',
	}
	return code_types_to_architectures[arch_code_type_name]

recognized_versions = [
	6,
	104
]

log_search = False

def reformat_UUID(UUID):
	"Takes a plain-hex-number UUID, uppercases it, and inserts hyphens."
	UUID = UUID.upper()
	if len(UUID) == 36:
		# Already hyphenated.
		pass
	else:
		UUID = '-'.join([UUID[0:8], UUID[8:12], UUID[12:16], UUID[16:20], UUID[20:]])
	return UUID

dSYM_cache = {} # Keys: UUIDs; values: dSYM bundle paths (None indicating dSYM bundle not found)
def find_dSYM_by_UUID(UUID):
	if log_search:
		print >>debug_log_file, 'Finding dSYM bundle for UUID', UUID
	try:
		dSYM_path = dSYM_cache[UUID]
	except KeyError:
		mdfind = subprocess.Popen(['mdfind', 'com_apple_xcode_dsym_uuids = ' + reformat_UUID(UUID)], stdout=subprocess.PIPE)

		try:
			dSYM_path = iter(mdfind.stdout).next()[:-1] # Strip \n
			
			if dSYM_path.endswith(".xcarchive"):
				dSYM_folder = os.path.join(dSYM_path, "dSYMs")
				dSYMs = filter(lambda d: d.endswith(".dSYM"), os.listdir(dSYM_folder))
				# I only know how to handle the case for one dSYM. I'm sure
				# there's a way to figure out which we want for multiple-dSYM
				# xcarchives (if such a thing exists?).
				if len(dSYMs) == 1:
					dSYM_path = os.path.join(dSYM_path, "dSYMs", dSYMs[0])
				else:
					dSYM_path = None
					if log_search:
						print >>debug_log_file, 'Found matching xcarchive, but contains multiple dSYMs and we don\'t know which to choose', dSYM_path
		except StopIteration:
			dSYM_path = None

		mdfind.wait()

		dSYM_cache[UUID] = dSYM_path

	if log_search:
		print >>debug_log_file, 'Found:', dSYM_path
	return dSYM_path

def find_dSYM_by_bundle_ID(bundle_ID):
	if log_search:
		print >>debug_log_file, 'Finding dSYM bundle for', bundle_ID
	if bundle_ID in binary_images:
		return find_dSYM_by_UUID(binary_images[bundle_ID])
	elif bundle_ID.startswith('...'):
		bundle_ID_suffix = bundle_ID.lstrip('...')
		for (bundle_ID_key, UUID) in binary_images.iteritems():
			if bundle_ID_key.endswith(bundle_ID_suffix):
				binary_images[bundle_ID] = UUID
				return find_dSYM_by_UUID(UUID)
		return None
	else:
		return None

def parse_binary_image_line(line):
	bundle_ID = ""
	UUID = ""

	match = binary_image_line_exp.search(line)
	line_at_bundle_start = match.group(1);
#	pdb.set_trace()
	for a_bundle_id in bundle_idents:
		if line_at_bundle_start.startswith( a_bundle_id + " " ):
			bundle_ID = a_bundle_id
			match = binary_image_uuid_exp.match( line )
			if not match:
				UUID = ""
			else:
				UUID = match.group('uuid')
			
			break

		elif a_bundle_id.startswith('...'):
			a_bundle_id_suffix = a_bundle_id.lstrip('...')
			index = line_at_bundle_start.find( a_bundle_id_suffix )
			# Crash Reporter truncates at 30, so the index we find the stub at + 27 should equal the 
			# entire length of the bundle ID
			if index != -1:
				bundle_ID = line_at_bundle_start[:index + 27]
				match = binary_image_uuid_exp.match( line )
				if not match:
					UUID = ""
				else:
					UUID = match.group('uuid')
				
				break
			
	return( bundle_ID, UUID )

def look_up_address_by_bundle_ID(bundle_ID, address, slide):
	dSYM_path = find_dSYM_by_bundle_ID(bundle_ID)
	if dSYM_path:
		dwarfdump = subprocess.Popen(['dwarfdump', '--arch=%s' % (architecture,), '--lookup', address, dSYM_path], stdout=subprocess.PIPE)

		tag_compile_unit = False
		tag_subprogram = False
		filename = function = None
		line_number = 0
		for line in dwarfdump.stdout:
			line = line.strip()
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

		if function:
			if line_number:
				format = '%(function)s (%(filename)s:%(line_number)s)'
			elif filename:
				format = '%(function)s (%(filename)s)'
			else:
				format = '%(function)s'
		else:
			if line_number:
				format = '%(filename)s:%(line_number)s'
			elif filename:
				format = '%(filename)s'
			else:
				format = None

		# If we found nothing, try to find something via the slide value (if one exists)
		if format is None:
			if slide is not None:
				return look_up_address_by_bundle_ID( bundle_ID, slide, None )
			else:
				return None

		return format % {
			'function': function,
			'filename': filename,
			'line_number': line_number,
		}
	else:
		return None

def symbolicate_backtrace_line(line):
	match = backtrace_exp.match( line )
	if not match:
		return line

	bundle_ID = match.group('bundle_ID').strip()
	address = match.group('address')

#	print >> sys.stderr, "bundle_ID: ", bundle_ID, "\n"

	slideMatch = backtrace_slide_exp.match( line )
	if slideMatch:
		slide = slideMatch.group('slide')
	else:
		slide = None

	function_info = look_up_address_by_bundle_ID(bundle_ID, address, slide)
	if function_info is None:
		return line
	else:
		return line[:match.end(0)] + function_info + '\n'

def bundle_ident_from_backtrace(line):
	match = backtrace_exp.match( line )
	if not match:
		return None
	
	bundle_ID = match.group('bundle_ID').strip()
	return( bundle_ID )

def main():
	parser = optparse.OptionParser(
		usage="%prog [options] [files]",
		description="Reads one or more crash logs from named files or standard input, symbolicates them, and writes them to standard output.",
		version='%prog 1.0.2 by Peter Hosey',
	)
	parser.add_option('--debug-log-fd', default=None, type='int', help='File descriptor to log debugging information to. Defaults to stderr.')
	parser.add_option('--log-dsyms', default=False, action='store_true', help='Logs the dSYM-bundle cache to the debug log.')
	parser.add_option('--log-search', default=False, action='store_true', help='Logs searches for dSYM bundles and the results of those searches to the debug logst. Does not distinguish between new searches and cache hits.')
	opts, args = parser.parse_args()
	global log_search
	log_search = opts.log_search
	global debug_log_file
	if opts.debug_log_fd is None:
		debug_log_file = sys.stderr
	else:
		debug_log_file = os.fdopen(opts.debug_log_fd, 'w')

	global binary_images
	binary_images = {} # Keys: bundle IDs; values: UUIDs
	global bundle_idents
	bundle_idents = []
	global architecture
	architecture = None
	global binary_image_line_exp, binary_image_uuid_exp
	global backtrace_exp
	global backtrace_slide_exp

	work = False
	is_in_backtrace = False
	is_in_thread_state = False
	is_in_binary_images = False
	backtrace_lines = []
	thread_state_lines = []
	binary_image_lines = []
	thread_trace_start_exp = re.compile('^Thread \d+( Crashed)?:\s*(Dispatch queue:.+)?$')
	binary_image_line_exp = re.compile(r'.*0x.*?0x.*? \+?(.*)$')
	binary_image_uuid_exp = re.compile('^.+\<(?P<uuid>[^\>]+)\>.+$')

	# It'd be preferred to have just one regex but the only character we have to key on is +, which 
	# would get us incorrect results when a class method is encountered.  backtrace_slide_exp takes
	# advantage of the fact that regexs are greedy by default.
	backtrace_exp = re.compile('(?P<frame_number>[0-9]+)\s+(?P<bundle_ID>[-_a-zA-Z0-9\./ ]+)\s+(?P<address>0x[0-9A-Fa-f]+)\s+' )
	backtrace_slide_exp = re.compile( '^[^\+]+\+\s(?P<slide>\d+)$' )

	def flush_buffers():
		for line in backtrace_lines:
			sys.stdout.write(symbolicate_backtrace_line(line))
		for line in thread_state_lines:
			sys.stdout.write(line)
		for line in binary_image_lines:
			sys.stdout.write(line)

	for line in fileinput.input(args):
		line_stripped = line.strip()
#		pdb.set_trace()
		if line_stripped.startswith('Incident Identifier:') or line_stripped.startswith('Process:'):
			if is_in_binary_images:
				# End previous crash
				flush_buffers()
				is_in_binary_images = False

			# New crash
			work = True
			is_in_backtrace = is_in_thread_state = is_in_binary_images = False
			sys.stdout.write(line)
		elif not work:
			continue
		elif line_stripped.startswith('Report Version:'):
			version = int(line_stripped[len('Report Version:'):])
			if version not in recognized_versions:
				print >>sys.stderr, 'Unrecognized crash log version:', version, '(skipping this crash log)'
				work = False
			sys.stdout.write(line)
		elif line_stripped.startswith('Code Type:'):
			architecture = architecture_for_code_type(line_stripped[len('Code Type:'):].strip())
			sys.stdout.write(line)
		elif thread_trace_start_exp.match(line_stripped):
			is_in_backtrace = True
			backtrace_lines.append(line)
		elif is_in_backtrace and ('Thread State' in line_stripped):
			is_in_backtrace = False
			is_in_thread_state = True
			thread_state_lines.append(line)
		elif line_stripped == 'Binary Images:':
			is_in_thread_state = False
			is_in_binary_images = True
			binary_image_lines.append(line)
		elif is_in_thread_state:
			thread_state_lines.append(line)

		elif is_in_backtrace:
			the_bundle_id = bundle_ident_from_backtrace(line)
			if the_bundle_id is not None:
				#binary_images[the_bundle_id] = None
				try:
#					print >> sys.stderr, "index: ", bundle_idents.index( the_bundle_id ), "\n"
					bundle_idents.index( the_bundle_id )
				except ValueError:
					bundle_idents.append( the_bundle_id )
				
			backtrace_lines.append(line)

		elif not is_in_binary_images:
			# We haven't gotten to backtrace or binary images yet. Pass this line through.
			sys.stdout.write(line)

		elif is_in_binary_images:
			if line_stripped.strip():
				binary_image_lines.append(line)
				bundle_ID, UUID = parse_binary_image_line(line)
				binary_images[bundle_ID] = UUID
			else:
				# End of crash
				flush_buffers()
				is_in_binary_images = False

	if is_in_binary_images:
		# Crash not followed by a newline
		flush_buffers()

	if opts.log_dsyms:
		for UUID in dSYM_cache:
			print >>debug_log_file, UUID, '=', dSYM_cache[UUID]

	debug_log_file.close()

if __name__ == '__main__':
	main()
