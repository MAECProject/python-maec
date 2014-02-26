# run_comparator script
# v0.11
# Runs the MAEC Comparator against a list or folder of MAEC files
import pprint
import sys
import os
import maec
from maec.bundle.bundle import Bundle
from maec.package.package import Package

USAGE_TEXT = """
MAEC Run Comparator Script v0.11 BETA
   *Performs Object->Object comparison of 2 or more input MAEC documents
   *Prints common/unique Objects between MAEC Bundles

Usage: python run_comparator.py -l <single whitespace separated list of MAEC files> OR -d <directory name>
"""

# Process a set of MAEC binding objects and extract the Bundles as appropriate
def process_maec_file(filename, bundle_list):
    parsed_objects = maec.parse_xml_instance(filename, check_version = False)
    if parsed_objects and isinstance(parsed_objects['api'], Package):
        package_obj = parsed_objects['api']
        if package_obj.malware_subjects:
            for malware_subject in package_obj.malware_subjects:
                for bundle in malware_subject.get_all_bundles():
                    bundle_list.append(bundle)
    elif parsed_objects and isinstance(parsed_objects['api'], Bundle):
        bundle_list.append(parsed_objects['api'])
        
def main():
    infilenames = []
    list_mode = False
    directoryname = ''
    # List of Bundle instances to compare
    bundle_list = []

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
            process_maec_file(file, bundle_list)
    elif directoryname != '':
        for filename in os.listdir(directoryname):
            if '.xml' not in filename:
                pass
            else:
                process_maec_file(os.path.join(directoryname, filename), bundle_list)

    # Matching properties dictionary
    match_on_dictionary = {'FileObjectType': ['file_path'],
                           'WindowsRegistryKeyObjectType': ['hive', 'key'],
                           'WindowsMutexObjectType': ['name'],
                           'WindowsProcessObjectType': ['name']}
    # Perform the comparison and get the results
    comparison_results = Bundle.compare(bundle_list, match_on = match_on_dictionary, case_sensitive = False)
    # Pretty print the common and unique Objects
    print "******Common Objects:*******\n"
    pprint.pprint(comparison_results.get_common())
    print "****************************"
    print "******Unique Objects:*******\n"
    pprint.pprint(comparison_results.get_unique())
    print "****************************"
if __name__ == "__main__":
    main()    