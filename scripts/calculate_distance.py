# calculate_distance script
# Calculates and prints the distance between two or more MAEC Malware Subjects
# NOTE: This code imports and uses the maec.analytics.distance module, which uses the external numpy library.
# Numpy can be found here: https://pypi.python.org/pypi/numpy

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
import maec
import argparse
from maec.analytics.distance import Distance
from maec.package.package import Package

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC Distance Calculation script")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "-list", nargs="+", help="a space separated list of MAEC Package files to calculate the distances for")
    group.add_argument("-d", "-directory", help="the path to a directory of MAEC Package files to calculate the distances for")
    parser.add_argument("--only_static", "--only_static", help="use only static features in the distance calculation", action="store_true")
    parser.add_argument("--only_dynamic", "--only_dynamic", help="use only dynamic features (Actions) in the distance calculation", action="store_true")
    parser.add_argument("output", help="the name of the CSV file to which the calculated distances will be written")
    args = parser.parse_args()
    package_list = []

    # Parse the input files
    if args.l:
        for file in args.l: 
            api_obj = maec.parse_xml_instance(file)['api']
            if isinstance(api_obj, Package):
                package_list.append(api_obj)
    elif args.d:
        for filename in os.listdir(args.d):
            if '.xml' not in filename:
                pass
            else:
                api_obj = maec.parse_xml_instance(os.path.join(args.d, filename))['api']
                if isinstance(api_obj, Package):
                    package_list.append(api_obj)

    # Perform the distance calculation
    dist = Distance(package_list)
    # Set the particular features that will be used
    if args.only_static:
        dist.options_dict['use_dynamic_features'] = False
    if args.only_dynamic:
        dist.options_dict['use_static_features'] = False
    dist.calculate()
    # Write the results to the specified CSV file
    out_file = open(args.output, mode='w')
    dist.print_distances(out_file)
    out_file.close()
    

if __name__ == "__main__":
    main()    