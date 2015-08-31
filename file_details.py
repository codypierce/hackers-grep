
import os
import win32com.client

# https://technet.microsoft.com/library/ee176615.aspx
def getFileDetails(abs_path):
	details = {}
	base_dir = os.path.dirname(abs_path)
	file_name = os.path.basename(abs_path)

	sh = win32com.client.Dispatch("Shell.Application")
	ns = sh.NameSpace(base_dir)

	try:
		idx = ns.ParseName(file_name)
	except:
		return None

	try:
		details["vendor"] = ns.GetDetailsOf(idx, 33)
		details["description"] = ns.GetDetailsOf(idx, 34)
	except:
		return None

	return details

