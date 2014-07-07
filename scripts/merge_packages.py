# merge_packages script
# v0.10 BETA
# Merges two or more MAEC Package documents (.xml files)
# Attempts to merge related Malware Subjects
import sys
import os
import maec
from maec.utils.merge import merge_documents

USAGE_TEXT = """
MAEC Package Merge Script v0.10 BETA
   *Merges two or more MAEC Package XML documents
   *Attempts to merge related (e.g., same MD5 hash) Malware Subjects

Usage: python merge_packages.py -o <output file name> -l <single whitespace separated list of MAEC Package files> OR -d <directory name>
"""

def main():
    infilenames = []
    list_mode = False
    directoryname = ''
    outfilename = ''

    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 3:
        print USAGE_TEXT
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-l':
            list_mode = True
        elif args[i] == '-d':
            directoryname = args[i+1]

    if outfilename == '':
        print USAGE_TEXT
        sys.exit(1)

    sys.stdout.write("Merging...")
    # Get the list of input files and perform the merge operation
    if list_mode:
        files = args[3:]
        merge_documents(files, outfilename)
    elif directoryname != '':
        file_list = []
        for filename in os.listdir(directoryname):
            if '.xml' not in filename:
                pass
            else:
                file_list.append(os.path.join(directoryname, filename))
        merge_documents(file_list, outfilename)
    sys.stdout.write("Done.")

if __name__ == "__main__":
    main()    
