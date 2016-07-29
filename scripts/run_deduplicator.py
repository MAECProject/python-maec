# run_deduplicator script
# v0.10 BETA
# Runs the MAEC Deduplicator against a list or folder of MAEC files
import sys
import os
import argparse
import timeit
import maec
from maec.bundle.bundle import Bundle
from maec.package.package import Package

USAGE_TEXT = """
MAEC Run Deduplicator Script v0.10 BETA
   *Performs Object-based Deduplication on one or more input MAEC Documents
   *Saves deduplicated documents as <original_document_name>_deduplicated.xml

Usage: python run_deduplicator.py -l <single whitespace separated list of MAEC files> OR -d <directory name>
"""

# Process a set of MAEC binding objects and peform the deduplication as appropriate
def process_maec_file(filename):
    fn, ext = os.path.splitext(filename)
    new_filename = "%s_deduplicated.xml" % fn
    start_time = timeit.default_timer()
    parsed_objects = maec.parse_xml_instance(filename)
    print "Parsing: " + str(timeit.default_timer() - start_time)

    start_time = timeit.default_timer()
    if parsed_objects and isinstance(parsed_objects['api'], Package):
        parsed_objects['api'].deduplicate_malware_subjects()
        parsed_objects['api'].to_xml_file(new_filename)
    elif parsed_objects and isinstance(parsed_objects['api'], Bundle):
        parsed_objects['api'].deduplicate()
        parsed_objects['api'].to_xml_file(new_filename)

    elapsed = timeit.default_timer() - start_time
    print "Deduplicating: %s" % elapsed

def main():
    parser = argparse.ArgumentParser(description=USAGE_TEXT)
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument(
        '-l', '--list', nargs='+',
        help='single whitespace separated list of MAEC files'
    )
    mutex_group.add_argument(
        '-d', '--directory',
        help='directory name'
    )
    args = parser.parse_args()

    #sys.stdout.write("Deduplicating.")
    infilenames = []
    list_mode = False
    directoryname = ''

    # Parse the input files and get the MAEC Bundles from each
    if args.list:
        for file in args.list:
            #sys.stdout.write(".")
            process_maec_file(file)
    elif args.directory:
        for filename in os.listdir(args.directory):
            sys.stdout.write(".")
            if '.xml' not in filename:
                pass
            else:
                process_maec_file(os.path.join(args.directory, filename))
    #sys.stdout.write("Done.")
if __name__ == "__main__":
    main()    
