# MAEC to YAML output script
# v0.10 BETA
# Requires pyyaml - http://pyyaml.org/

try:
    import yaml
except ImportError:
    sys.stdout.write("Error: failed to import required pyyaml module. Please install the pyyaml library (http://pyyaml.org). Exiting\n")
    sys.exit(0)
import sys
import maec
from maec.package.package import Package
from maec.bundle.bundle import Bundle
from collections import OrderedDict

USAGE_TEXT = """
MAEC to YAML output script v0.10 BETA
   *Prints a YAML representation of an input MAEC document
   *Capable of printing simplified MAEC Package and Bundle output, with the following data:
      **Malware Instance Object Attributes
      **Findings Bundles
      **Capabilities
      **Actions
      **Objects
      **Action Collections
      **Object Collections

   *REQUIRES: pyyaml library - http://pyyaml.org

Usage: python maec_to_yaml.py -m <mode> -i <maec XML file> [optional: -o <yaml output filename>]
           Required parameters:
               -m: the output mode to use. Possible values: simple, full.
                   'simple' will print a simplified, pruned version of the input.
                   'full' will print the full input.
               -i: the path to the input MAEC Package or Bundle to output.
                
            Optional parameters:
               -o: the path the output file to which the YAML will be written. If not specified,
                   this defaults to stdout.

        E.g.: python maec_to_yaml.py -m simple -i maec_package.xml -o yaml_out.txt
"""

# Properties that are allowed to be displayed in the output
allowed_properties = ['malware_subjects', 'malware_instance_object_attributes', 'findings_bundles',
                     'bundles', 'bundle', 'collections', 'action_collections', 'object_collections',
                     'name','capabilities', 'capability', 'strategic_objective', 'tactical_objective',
                     'action_list', 'object_list', 'timestamp', 'association_type', 'value', 
                     'associated_objects', 'properties', 'description', 'actions', 'objects']
# Properties disallowed on ANY type
disallowed_properties = ['id', 'xsi:type', 'schema_version', 'defined_subject', 'content_type',
                         'action_status', 'context', 'idref', 'ordinal_position']
# Properties that are passed through unchanged (relatively speaking)
passedthrough_properties = ['properties']

def ordered_key_test(dict):
    for key in dict.keys():
        if key in allowed_properties:
            return True
    return False

# Normalize the MAEC objects
def normalize_maec(obj):
    if isinstance(obj, Package):
        for malware_subject in obj.malware_subjects:
            # Dereference any Objects
            malware_subject.dereference_bundles()
    elif isinstance(obj, Bundle):
         # Dereference any Objects
        obj.dereference_objects()
    return obj

def prune_dict(obj, passedthrough = False, replacement = None):
    if type(obj) == dict:
        for k, v in obj.items():
            if not v:
                obj.pop(k)
                continue
            # Special exception for object properties
            if k in passedthrough_properties:
                passedthrough = True

            if hasattr(v, '__iter__'):
                if not passedthrough and k not in allowed_properties:
                    obj.pop(k)
                else:
                    prune_dict(v, passedthrough)
            else:
                if k in disallowed_properties:
                    obj.pop(k)
                    
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                prune_dict(v, passedthrough, replacement)
    return obj

def order_dict(obj):
    if type(obj) == dict:
        for k, v in obj.items():
            if k in passedthrough_properties:
                continue
            elif hasattr(v, '__iter__'):
                obj[k] = order_dict(v)
    elif type(obj) == list:
        new_list = []
        for v in obj:
            if hasattr(v, '__iter__'):
                new_list.append(order_dict(v))
        obj = new_list

    # Convert the dictionary into an Ordered Dictionary
    if type(obj) == dict and ordered_key_test(obj):
        try:
            obj = OrderedDict(sorted(obj.items(), key=lambda x: allowed_properties.index(x[0])))
        except ValueError:
            pass
    elif type(obj) == dict:
        obj = OrderedDict(obj.items())
    return obj

def main():
    infilename = None
    outfilename = None
    mode = None

    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 4:
        print USAGE_TEXT
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
        elif args[i] == '-m':
            mode = args[i+1]

    if mode not in ['simple', 'full']:
        sys.stdout.writelines("Error: incorrect output mode specified. Possible values are 'simple' and 'full'\n")
        sys.exit(0)
    objects_dict = maec.parse_xml_instance(infilename, check_version = False)
    # Normalize the MAEC object
    normalized_obj = normalize_maec(objects_dict['api'])
    api_obj_dict = normalized_obj.to_dict()
    output_dict = {}
    if mode == 'simple':
        # Prune the MAEC dictionary
        pruned_dict = prune_dict(api_obj_dict)
        # Add the custom YAML representer
        def order_rep(dumper, data):
            return dumper.represent_mapping( u'tag:yaml.org,2002:map', data.items(), flow_style=False )
        yaml.add_representer( OrderedDict, order_rep )
        output_dict = order_dict(api_obj_dict)
    elif mode == 'full':
        output_dict = api_obj_dict
    # Output the pruned dictionary as YAML
    if outfilename:
        outfile = open(outfilename, 'w')
        outfile.write(yaml.dump(output_dict, default_flow_style=False))
        outfile.flush()
        outfile.close()
    else:
        sys.stdout.write(yaml.dump(output_dict, default_flow_style=False))

if __name__ == "__main__":
    main()    