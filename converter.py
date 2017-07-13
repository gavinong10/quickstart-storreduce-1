

import sys

source_file = sys.argv[1]

myfile = open(source_file, "r")
lines = "".join(myfile.readlines())

before = r'"'
after = r'\"'
output = lines.strip().replace(before, after)

before = '\n'
after = '\\n",\n"'
output = output.replace(before, after)
output = '\"' + output + '\"'
print output