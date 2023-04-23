import os
target_file = '../mem/ACTF.mem'
command = 'windows.info'
ping = 'ping'
# os.system(ping + ' google.com')

# OS INFORMATION - 

# ImageInfo
os.system('python vol.py -f "./mem/ACTF.mem" windows.info')

# PROCESS INFORMATION -

# Pslist
os.system('python vol.py -f "./mem/ACTF.mem" windows.pslist')
os.system('python vol.py -f "./mem/ACTF.mem" windows.psscan')
os.system('python vol.py -f "./mem/ACTF.mem" windows.pstree')

# Procdump
# os.system('python vol.py -f "./mem/ACTF.mem" -o "/path/to/dir" windows.dumpfiles ‑‑pid <PID>')

# Memdump
# os.system('python vol.py -f "./mem/ACTF.mem" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid <PID>')

# Handles 
# os.system('python vol.py -f "./mem/ACTF.mem" windows.handles ‑‑pid <PID>')

# DLLs
# os.system('python vol.py -f "./mem/ACTF.mem" windows.dlllist ‑‑pid <PID>')

# Cmdline
os.system('python vol.py -f "./mem/ACTF.mem" windows.cmdline')

# NETWORK INFORMATION -

# Netscan 
os.system('python vol.py -f "./mem/ACTF.mem" windows.netscan')
os.system('python vol.py -f "./mem/ACTF.mem" windows.netstat')

# REGISTRY -

# Hivelist
os.system('python vol.py -f "./mem/ACTF.mem" windows.registry.hivescan')
os.system('python vol.py -f "./mem/ACTF.mem" windows.registry.hivelist')

# Printkey
os.system('python vol.py -f "./mem/ACTF.mem" windows.registry.printkey')
os.system('python vol.py -f "./mem/ACTF.mem" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion"')

# Hivedump
# shayad chale ya naa chale yeh wala
print('does it work???')
# os.system('python vol.py -f "./mem/ACTF.mem" ‑‑profile hivedump -o <offset>')
print('hivedump over!')

# FILES

# Filescan
os.system('python vol.py -f "./mem/ACTF.mem" windows.filescan')

# Filedump 
os.system('python vol.py -f "./mem/ACTF.mem" -o "/path/to/dir" windows.dumpfiles')
# os.system('python vol.py -f "./mem/ACTF.mem" -o "/path/to/dir" windows.dumpfiles ‑‑virtaddr <offset>')
# os.system('python vol.py -f "./mem/ACTF.mem" -o "/path/to/dir" windows.dumpfiles ‑‑physaddr <offset>')

# MISCELLANEOUS -

# Malfind
os.system('python vol.py -f "./mem/ACTF.mem" windows.malfind')

# Yarascan
# applies to yara files only ig?
# os.system('python vol.py -f "./mem/ACTF.mem" windows.vadyarascan ‑‑yara-rules <string>')
# os.system('python vol.py -f "/path/to/file" windows.vadyarascan ‑‑yara-file "/path/to/file.yar"')
# os.system('python vol.py -f "/path/to/file" yarascan.yarascan ‑‑yara-file "/path/to/file.yar"')




