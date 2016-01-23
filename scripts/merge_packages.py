# merge_packages script
# v0.10 BETA
# Merges two or more MAEC Package documents (.xml files)
# Attempts to merge related Malware Subjects
import sys
import os
import argparse
import maec
from maec.utils.merge import merge_documents

USAGE_TEXT = """
MAEC Package Merge Script v0.10 BETA
   *Merges two or more MAEC Package XML documents
   *Attempts to merge related (e.g., same MD5 hash) Malware Subjects
"""

def main():
    parser = argparse.ArgumentParser(description=USAGE_TEXT)
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    required_group = parser.add_argument_group('required arguments')
    mutex_group.add_argument(
        '-l', '--list', nargs='+',
        help='single whitespace separated list of MAEC Package files'
    )
    mutex_group.add_argument(
        '-d', '--directory',
        help='directory name'
    )
    required_group.add_argument(
        '-o', '--output', required=True,
        help='output file name'
    )
    args = parser.parse_args()

    sys.stdout.write("Merging...")
    # Get the list of input files and perform the merge operation
    if args.list:
        merge_documents(args.list, args.output)
    elif args.directory:
        file_list = []
        for filename in os.listdir(args.directory):
            if '.xml' not in filename:
                pass
            else:
                file_list.append(os.path.join(args.directory, filename))
        merge_documents(file_list, args.output)
    sys.stdout.write("Done.")

if __name__ == "__main__":
    main()    