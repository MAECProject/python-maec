# MAEC 4.0.1 to MAEC 4.1 Converter Script
# Translates a MAEC 4.0.1 Package or Bundle into a valid MAEC 4.1 Package or Bundle

import sys
import os
import shutil
import maec
from maec.bundle.bundle import Bundle
from maec.package.package import Package

# Update the MAEC v4.0.1 file to MAEC v4.1
def update_maec(infilename, outfilename):
    # Parse the input document using the parse_xml_instance() method
    maec_objects = maec.parse_xml_instance(infilename, check_version = False)

    # Get the API Object from the parsed input
    api_object = maec_objects['api']

    # Determine if we're dealing with a Package or Bundle
    if isinstance(api_object, Package):
        # Update the Package schema_version
        api_object.schema_version = "2.1"
        for malware_subject in api_object.malware_subjects:
            for analysis in malware_subject.analyses:
                # Replace the Analysis type value of "manual" with "in-depth"
                if analysis.type and analysis.type == "manual":
                    analysis.type = "in-depth"
            # Update the schema_versions on the Bundles
            for bundle in malware_subject.findings_bundles.bundles:
                bundle.schema_version = "4.1"
    elif isinstance(api_object, Bundle):
        # Update the Bundle schema_version
        api_object.schema_version = "4.1"

    # Output the updated MAEC object to XML
    api_object.to_xml_file(outfilename)

# Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
MAEC 4.0.1 --> MAEC 4.1 XML Converter Utility

Usage: python maec_4.0.1_to_4.1.py -i <input maec 4.0.1 xml file> -o <output maec 4.1 xml file>
"""    

def main():
    infilename = None
    outfilename = None
    directoryname = ''
    filepath = ''
    
    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 2:
        usage()
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-d':
            directoryname = args[i+1]

    if directoryname != '':
        for filename in os.listdir(directoryname):
            print filename
            if '.xml' not in filename:
                pass
            elif '_report.maec-4.0.1' not in filename:
                update_maec(os.path.join(directoryname, filename), filename.rstrip('.xml') + '_cuckoobox_maec.xml')
            else:
                new_filepath = os.path.join(directoryname, filename.replace('_report.maec-4.0.1', ''))
                shutil.move(os.path.join(directoryname, filename), new_filepath)
                update_maec(new_filepath, new_filepath.rstrip('.xml') + '_cuckoobox_maec.xml')

    # Basic parameter checking
    elif infilename and outfilename:
        update_maec(infilename, outfilename)
        
if __name__ == "__main__":
    main()

