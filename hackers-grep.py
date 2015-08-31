#!/usr/bin/env python

'''

hackers-grep.py: Search for regex patterns in the public symbols,
				 exports, imports, and strings of PE files

-Cody

'''

import sys, os, re, time, string, dislib
import logging
import threading
from multiprocessing import current_process, Process, Queue, Lock, Pool
from optparse import OptionParser

try:
	import win32com
except ImportError:
	print "[!] Please install pywin32 (http://sourceforge.net/projects/pywin32/)"
	sys.exit(1)

try:
	import comtypes
except ImportError:
	print "[!] Please install comtypes (https://pypi.python.org/pypi/comtypes)"
	sys.exit(1)

import dislib
from pdbsymbols import PdbFile
from file_details import getFileDetails

LOGGER_NAME = "hackers_grep"
g_logger = None
g_log_level = logging.INFO

TYPE_IMPORT = 1
TYPE_EXPORT = 2

def log_init(log_level):
	global g_logger
	global g_log_level

	g_log_level = log_level

	g_logger = logging.getLogger(LOGGER_NAME)
	g_logger.setLevel(log_level)

	log_handler = logging.StreamHandler()
	log_handler.setLevel(log_level)
	log_format = logging.Formatter("%(levelname)s - %(message)s")
	log_handler.setFormatter(log_format)

	g_logger.addHandler(log_handler)
	
def debug(m):
	if g_logger == None:
		log_init()
	g_logger.debug(m)

def error(m):
	if g_logger == None:
		log_init()
	g_logger.error(m)

def info(m):
	if g_logger == None:
		log_init()
	g_logger.info(m)

def get_public_symbols(pdb_file):
	symbols = []
	p = PdbFile(pdb_file)
	p.setup()
	p.get_public()
	for sym in p.public:
		symbols.append(sym.undecorated_name)
	return symbols
	
def walk_dir(top, files, max_depth=1):
	if os.path.exists(top) == False:
		raise Exception, "Unknown directory %s" % top
	if max_depth == 0:
		return False
	else:
		max_depth -= 1
	for dirpath, dirnames, filenames in os.walk(top):
		for f in filenames:
			files.append(os.path.join(top, f))
		if max_depth > 0:
			rc = True
			for d in dirnames:
				try:
					rc = walk_dir(os.path.join(top, d), files, max_depth=max_depth)
				except:
					pass
				if rc == False:
					break
	return True

def make_cstring(chars, nonprintable=False, min_length=3):
	if len(chars) >= min_length:
		if nonprintable == False:
			chars = ''.join(s for s in chars if s in string.printable)
		return chars

	return False

def make_wstring(chars, nonprintable=False, min_length=3):
	c = chars.replace("\x00", "")
	if len(c) >= min_length:
		if nonprintable == False:
			c = ''.join(s for s in c if s in string.printable)
		return c

	return False

# Matches the string regex to files exports
def match_exports(pef, string_regex):
	sre = re.compile(string_regex, re.I)

	strings = []        
	if pef.Exports:
		for i in pef.Exports:
			if sre.match(i.Name):
				strings.append("<export>!%s" % (i.Name))
	return strings

def get_dll_search_paths(abs_path, module_name):
	search_dirs = []
	
	# https://msdn.microsoft.com/en-us/library/7d83bc18.aspx
	# module cwd
	search_dirs.append(os.path.dirname(abs_path))

	# Windows system dir/root/path
	for p in os.environ["PATH"].split(';'):
		search_dirs.append(p)

	return search_dirs


def get_pe(abs_path, module_name):
	search_dirs = get_dll_search_paths(abs_path, module_name)

	for dll_path in search_dirs:
		ap = os.path.join(dll_path, module_name)
		if not os.path.exists(ap):
			continue
		try:
			pe = dislib.PEFile(ap)
			pe.LoadExports()
			return pe
		except Exception, exc:
			return None
	return None

# TODO: dislib doesnt understand delayed imports and has a bug loading some dlls ymmv
imap = {}

# Matches the string regex to files imports
def match_imports(pef, pe_path, string_regex):
	global imap
	sre = re.compile(string_regex, re.I)

	strings = []
	if pef.Imports:
		for i in pef.Imports:
			if i.ModuleName not in imap.keys():
				imap[i.ModuleName] = {}
				im = get_pe(pe_path, i.ModuleName)
				imap[i.ModuleName]['im'] = im
				imap[i.ModuleName]['ords'] = {}
				if not im:
					debug("Cant find %s" % i.ModuleName)
				else:
					if im.Exports:
						for x in im.Exports:
							if isinstance(x.Ordinal, int) and x.Name != "":
								imap[i.ModuleName]['ords'][x.Ordinal] = x.Name

			if "Ord_" in i.Name:
				if imap[i.ModuleName]['im']:
					ordinal = int(i.Name.split('x')[1], 16)
					if ordinal in imap[i.ModuleName]['ords']:
							name = imap[i.ModuleName]['ords'][ordinal]
							if sre.match(name) or sre.match(i.ModuleName):
								strings.append("%s!%s" % (i.ModuleName, name))
			elif sre.match(i.Name) or sre.match(i.ModuleName):
				strings.append("%s!%s" % (i.ModuleName, i.Name))
	return strings

def GetSectionByOrig(pe, ov):
	for s in pe.Sections:
		if ov >= (pe.ImageBase + s.VA) and ov <= (pe.ImageBase + s.VA + s.Size):
			return s
	return False

def dump_section(s):
	print "name:\t%s" % s.Name
	print "va:\t%x" % s.VA
	print "size:\t%x" % s.Size
	print "data size:\t%x" % len(s.Data)

def match_string(pef, pe_path, string_regex, import_filter=None, export_filter=None, symbols=False, symbol_path=None, min_string=3, max_string=1024):
	sre = re.compile(string_regex, re.I)

	if symbols:
		if not symbol_path:
			info("Asking to search symbols with no path, skipping symbol search")
			symbols = False
		elif os.path.isdir(symbol_path) == False:
			info("Symbol path %s is not a directory, skipping symbol search" % symbol_path)
			symbols = False
			
	c_strings = []
	w_strings = []

	# crack any strings in the relocations
	if pef.Relocs:
		relocs = pef.Relocs
		sec_dict = {}
		# pre pop for speed
		for s in pef.Sections:
			sec_dict[s.Name] = s
		seen_it = {}
		for r in relocs:
			offset = r.Offset
			original_value = r.OriginalValue
			section = r.Section
			addr = r.RelocAddr

			try:
				seen_it[original_value] += 1
				continue
			except:
				seen_it[original_value] = 1

			s = sec_dict[section.Name]
			str_offset = original_value - (pef.ImageBase + s.VA)
			if str_offset >= s.Size or str_offset < 0:
				# this is a hack
				real_sec = GetSectionByOrig(pef, original_value)
				if real_sec == False:
					continue
				if real_sec.Name != section.Name:
					s = sec_dict[real_sec.Name]
					str_offset = original_value - (pef.ImageBase + s.VA)
					if str_offset >= s.Size or str_offset < 0:
						continue
				else:
					continue
			
			# skip idata
			if s.Name in [".idata"]:
				continue

			try:
				sec_data = s.Data
				if sec_data[str_offset] in string.printable:
					# find null
					for x in xrange(16, max_string, 16):
						s = sec_data[str_offset:str_offset+x]
						n = s.find("\x00")
						if n == -1:
							continue
						if n <= min_string:
							# try wchar
							n = s.find("\x00\x00")
							if n == -1:
								continue
							else:
								s = sec_data[str_offset:str_offset+n].replace("\x00", "")
								w_strings.append(s)
								break
						else:
							s = sec_data[str_offset:str_offset+n]
							c_strings.append(s)
							break
			except IndexError:
				error("Index error in sec_data str_offset %x" % str_offset)
				break

	# Crack any strings from .text or .data or .rdata
	# XXX: refactor plz
	for sec in pef.Sections:
		if "text" in sec.Name or "data" in sec.Name:
			nulls = sec.Data.split("\x00")
			
			for n in nulls:
				s = make_cstring(n, nonprintable=False)
				if s:
					c_strings.append(s)
			
			nulls = sec.Data.split("\x00\x00")
			for n in nulls:
				s = make_wstring(n, nonprintable=False)
				if s:
					w_strings.append(s)

	# If we are also searching symbols lets parse those out
	symbol_strings = []
	if symbols:
		pdb_files = []
		public_symbols = None
		pdb_search_path = os.path.join(symbol_path, os.path.basename(pe_path).split(os.path.extsep)[0]) + os.path.extsep + "pdb"
		debug("Getting symbols from %s" % pdb_search_path)
		if os.path.exists(pdb_search_path):
			rc = walk_dir(pdb_search_path, pdb_files, max_depth=2)
			if rc == True:
				for p in pdb_files:
					if os.path.exists(p):
						break
				public_symbols = get_public_symbols(p)
				if public_symbols:
					for sym in public_symbols:
						symbol_strings.append(sym)
		else:
			debug("Invalid symbol path %s ignoring search" % pdb_search_path)
				
	match_strings = []
	# check c strings
	for s in c_strings:
		if sre.match(s):
			match_strings.append(unicode(s, errors="ignore"))
	# check wchar strings
	for s in w_strings:
		if sre.match(s):
			match_strings.append(unicode(s, errors="ignore"))

	# check symbol strings
	for s in symbol_strings:
		if sre.match(s):
			match_strings.append(s)

	return match_strings
		
def dump_match(file_path, match_string, justify=None, show_info=False):
	output = ""
	if justify:
		for x in range(justify - len(file_path)): file_path += " "

	if show_info:
		(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file_path)
		if size < 1024:
			size_o = "B"
		else:
			size_o = "KB"
			size /= 1024
		details = getFileDetails(file_path)
		if details == None:
			vendor = "None"
			description = "None"
		else:
			vendor = details["vendor"]
			description = details["description"]

		output = u"%s  [%5d %s] [%s] [%s] [%s] " % (file_path, size, size_o, time.strftime("%m/%d/%Y", time.gmtime(mtime)), vendor, description)
	else:
		output = u"%s  " % (file_path)
	
	output += match_string

	try:
		print output.encode("ascii", errors="backslashreplace")
	except UnicodeEncodeError, e:
		error("Unicode exception printing match for %s" % file_path)

def file_grep(pe_path, string_regex, log_level, att=False, exports_only=False, imports_only=False, import_filter=None, export_filter=None, symbols=False, symbol_path=None):
	# open PE file
	try:
		pef = dislib.PEFile(pe_path)
	except dislib.PEException, e:
		debug("%s: %s" % (pe_path, e))
		return False

	# apply filters
	ire = None
	ere = None

	if import_filter:
		ire = re.compile(import_filter, re.I)
	if export_filter:
		ere = re.compile(export_filter, re.I)

	if ire:
		bail = True
		if pef.Imports:
			for i in pef.Imports:
				if ire.match(i.Name) or ire.match(i.ModuleName):
					bail = False
		if bail:
			return False

	if ere:
		bail = True
		if pef.Exports:
			for e in pef.Exports:
				if ere.match(e.Name):
					bail = False
		if bail:
			return False

	matched_strings = []
	if att:
		matched = match_exports(pef, string_regex)
		if matched:
			matched_strings += matched

		matched = match_imports(pef, pe_path, string_regex)
		if matched:
			matched_strings += matched

		matched = match_string(pef, pe_path, string_regex, import_filter=import_filter, export_filter=export_filter, symbols=symbols, symbol_path=symbol_path)
		if matched:
			matched_strings += matched

	elif exports_only:
		matched_strings = match_exports(pef, string_regex)
	elif imports_only:
		matched_strings = match_imports(pef, pe_path, string_regex)
	else:
		matched_strings = match_string(pef, pe_path, string_regex, import_filter=import_filter, export_filter=export_filter, symbols=symbols, symbol_path=symbol_path)
	return matched_strings

def run_grep(abs_path, string_regex, log_level, **kwargs):
	log_init(log_level)

	matched_strings = []
	ms = file_grep(abs_path, string_regex, log_level, **kwargs)
	if ms:
		for matched_string in ms:
			matched_strings.append((abs_path, matched_string))
	else:
		return None
	return matched_strings


# If using this on 64 bit windows c:\windows\system32 is c:\windows\syswow64 in 32 bit python due
# to the WOW64 file system redirector
if __name__ == '__main__':
	# parse options
	usage = "usage: %prog [options] <search path> <file regex> <string regex>"
	parser = OptionParser(usage=usage)
	parser.add_option("-d", "--max-depth", dest="max_depth", type="int", default=1, help="Maximum directory recursion depth (default: 1)")
	parser.add_option("-x", "--exports-only", dest="exports_only", action="store_true", default=False, help="Only search Export section strings")
	parser.add_option("-n", "--imports-only", dest="imports_only", action="store_true", default=False, help="Only search Import section strings")
	parser.add_option("-a", "--all-the-things", dest="att", action="store_true", default=False, help="Search strings, import, exports")
	parser.add_option("-s", "--symbols", dest="symbols", action="store_true", default=False, help="Include symbols in search")
	parser.add_option("-p", "--symbol-path", dest="symbol_path", type="str", default=r'C:\Windows\Symbols', help="Symbol path")
	parser.add_option("-e", "--export-filter", dest="export_filter", help="Search modules matching this Export regex")
	parser.add_option("-i", "--import-filter", dest="import_filter", help="Search modules matching this Import regex")
	parser.add_option("-f", "--show-info", dest="show_info", action="store_true", default=False, help="Display file details size and modification time")
	parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
	#parser.add_option("-h", "--help")
	(options, args) = parser.parse_args()

	try:
		directory = args[0]
		file_regex = args[1]
		string_regex = args[2]
	except IndexError:
		parser.print_help()
		sys.exit(1)
	
	# set up logging
	log_level = logging.INFO
	if options.verbose:
		log_level = logging.DEBUG

	log_init(log_level)

	if os.path.isdir(directory) == False:
		raise Exception, "%s not a directory" % directory
	
	exports_only = False
	if options.exports_only:
		exports_only = options.exports_only
	
	imports_only = False
	if options.imports_only:
		imports_only = options.imports_only
	
	if exports_only and imports_only:
		error("Options --exports-only and --imports-only are mutually exclusive")
		parser.print_help()
		sys.exit(1)
		
	symbols = False
	if options.symbols:
		symbols = options.symbols
		
	symbol_path = None
	if options.symbol_path:
		symbol_path = options.symbol_path
	
	show_info = False
	if options.show_info:
		show_info = options.show_info
  
	att = False
	if options.att:
		att = options.att

	stime = int(time.time())

	depth = 1
	if options.max_depth:
		depth = options.max_depth

	files = []
	walk_dir(directory, files, max_depth=depth)
	
	try:
		fre = re.compile(file_regex)
	except Exception, e:
		error("Invalid File Regex")
		error("%s" % str(e))
		sys.exit(1)
	
	file_list = []
	for f in files:
		abs_filename = os.path.basename(f)
		if fre.match(abs_filename):
			debug("Adding file %s" % f)
			file_list.append(f)

	debug("Starting workers")
	pool = Pool()
	results = []
	results = [pool.apply_async(run_grep, (f, string_regex, log_level),
										{'att': att,
										 'exports_only': exports_only,
										 'imports_only': imports_only,
										 'import_filter': options.import_filter,
										 'export_filter': options.export_filter,
										 'symbols': symbols,
										 'symbol_path': symbol_path}) for f in file_list]
	
	debug("Checking %d results" % len(results))
	matches = []
	while len(results) > 0:
		for result in results:
			if result.ready():
				m = result.get()
				if m:
					matches += m
				results.remove(result)
		time.sleep(.1)
	

	debug("Processing matches")

	# get max file path length to pretty up the text
	adjust = 0
	for (f, s) in matches:
		if len(f) > adjust:
			adjust = len(f)
		
	for (f, s) in matches:
		dump_match(f, s, justify=adjust, show_info=show_info)

	etime = int(time.time())
	debug("Finished in %d seconds" % (etime - stime))

