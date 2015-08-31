#hackers-grep
hackers-grep is a tool that enables you to search PE files for interesting functionality

#Installation

1. Install comtypes (https://pypi.python.org/pypi/comtypes)
2. Install pywin32 (http://sourceforge.net/projects/pywin32/files/pywin32/)
3. Install Microsoft debugging symbols (https://msdn.microsoft.com/en-us/windows/hardware/gg463028.aspx)

#Usage

The options for hackers-grep are listed below. Keep in mind that all regular expression strings should use pythons "re" module sytax and are case insensitive. For more information please see https://docs.python.org/2/library/re.html.

```
Z:\hackers-grep>hackers-grep.py -h
Usage: hackers-grep.py [options] <search path> <file regex> <string regex>

Options:
  -h, --help            show this help message and exit
  -d MAX_DEPTH, --max-depth=MAX_DEPTH
                        Maximum directory recursion depth
  -x, --exports-only    Only search Export section strings
  -n, --imports-only    Only search Import section strings
  -a, --all-the-things  Search strings, import, exports
  -s, --symbols         Include symbols in search
  -p SYMBOL_PATH, --symbol-path=SYMBOL_PATH
                        Symbol path
  -e EXPORT_FILTER, --export-filter=EXPORT_FILTER
                        Search modules matching this Export regex
  -i IMPORT_FILTER, --import-filter=IMPORT_FILTER
                        Search modules matching this Import regex
  -f, --show-info       Display file details size and modification time
  -v, --verbose         Verbose output
```

#Examples

##Search for every dll that imports wininet!InternetOpen
```
Z:\hackers-grep>hackers-grep.py -n c:\windows\system32 .*.dll "InternetOpen[A,W]"
c:\windows\system32\msidcrl30.dll    WININET.dll!InternetOpenA
c:\windows\system32\msscp.dll    WININET.dll!InternetOpenA
c:\windows\system32\mssign32.dll    WININET.dll!InternetOpenA
c:\windows\system32\msnetobj.dll    WININET.dll!InternetOpenA
c:\windows\system32\oleprn.dll    WININET.dll!InternetOpenW
c:\windows\system32\urlmon.dll    WININET.dll!InternetOpenW
c:\windows\system32\winethc.dll    WININET.dll!InternetOpenW
c:\windows\system32\wuwebv.dll    WININET.dll!InternetOpenW
```
