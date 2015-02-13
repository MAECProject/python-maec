# run_deduplicator script
# v0.10 BETA
# Runs the MAEC Deduplicator against a list or folder of MAEC files
import pprint
import sys
import os
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
    new_filename = filename[:filename.find(".xml")] + "_deduplicated.xml"
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
    print "Deduplicating: " + str(timeit.default_timer() - start_time)

def main():
    #sys.stdout.write("Deduplicating.")
    infilenames = []
    list_mode = False
    directoryname = ''

    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 2:
        print USAGE_TEXT
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-l':
            list_mode = True
        elif args[i] == '-d':
            directoryname = args[i+1]

    # Parse the input files and get the MAEC Bundles from each
    if list_mode:
        files = args[1:]
        for file in files:
            #sys.stdout.write(".")
            process_maec_file(file)
    elif directoryname != '':
        for filename in os.listdir(directoryname):
            sys.stdout.write(".")
            if '.xml' not in filename:
                pass
            else:
                process_maec_file(os.path.join(directoryname, filename))
    #sys.stdout.write("Done.")
if __name__ == "__main__":
    main()    