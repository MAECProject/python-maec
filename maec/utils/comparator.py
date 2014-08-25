# MAEC Comparator Classes
import collections

class ComparisonResult(object):
    def __init__(self, bundle_list, lookup_table):
        self.lookup_table = lookup_table
        self.bundle_list = bundle_list
    
    def get_unique(self, bundle_list=None):
        unique_objs = {}
        
        if bundle_list is None:
            bundle_list = self.bundle_list
        
        for b in self.bundle_list:
            unique_objs[b.id_] = []
        
        for obj_hash in self.lookup_table:
            sources = BundleComparator.get_sources(self.lookup_table, obj_hash)
            if len(sources) == 1:
                result_index = sources[0]
                for unique_obj in self.lookup_table[obj_hash][result_index]:
                    unique_objs[result_index].append(unique_obj['object'].id_)
                
        return unique_objs
    
    def get_common(self, bundle_list=None):
        confirmed_objs = []
        
        if bundle_list is None:
            bundle_list = self.bundle_list
            
        for obj_hash in self.lookup_table:
            sources = BundleComparator.get_sources(self.lookup_table, obj_hash)
            if len(sources) > 1:
                confirmed_obj_dict = {}
                confirmed_obj_dict['object'] = obj_hash
                confirmed_obj_dict['object_instances'] = {}

                for key, obj_list in self.lookup_table[obj_hash].items():
                    confirmed_obj_dict['object_instances'][key] = []
                    for common_obj in obj_list:
                        confirmed_obj_dict['object_instances'][key].append(common_obj['object'].id_)

                if confirmed_obj_dict not in confirmed_objs:
                    confirmed_objs.append(confirmed_obj_dict)
                        
        return confirmed_objs
    
class SimilarObjectCluster(dict):
    def __init__(self):
        pass
        
    def add_object(self, obj, owner):
        if owner not in self:
            self[owner] = [{ 'object':obj, 'ownerBundle':owner }]
        else:
            self[owner].append({ 'object':obj, 'ownerBundle':owner })
        
    def get_object_by_owner_id(self, owner_id):
        return self[owner_id][0]["object"]
            
class BundleComparator(object):
    @classmethod
    def compare(cls, bundle_list, match_on = None, case_sensitive = True):
        cls.object_table = {}
        cls.case_sensitive = case_sensitive
        if not match_on:
            # Default matching properties
            cls.match_on = {
                            'FileObjectType': 
                                ['file_name', 'file_path'],
                            'WindowsRegistryKeyObjectType': 
                                ['hive','key'],
                            'WindowsMutexObjectType':
                                ['name'],
                            'SocketObjectType':
                                ['address_value', 'port_value'],
                            'WindowsPipeObjectType':
                                ['name'],
                            'ProcessObjectType':
                                ['name']}
        else:
            cls.match_on = match_on

        lookup_table = {}
        
        for bundle in bundle_list:
            for action in bundle.get_all_actions():
                cls.process_action(action, lookup_table, bundle.id_)
                    
            for obj in bundle.get_all_objects():
                cls.process_object(obj, lookup_table, bundle.id_)

        return ComparisonResult(bundle_list, lookup_table)
        
    @classmethod
    def process_action(cls, action, lookup_table, bundle):
        if action.associated_objects:
            for associated_object in action.associated_objects:
                # get actual object from associated object
                obj = associated_object
                cls.process_object(obj, lookup_table, bundle)

    @classmethod
    def process_object(cls, obj, lookup_table, bundle):
        # get hash string from object to use as key in lookup table
        # Make sure the object is one of the supported types in the match_on dictionary
        if obj.properties and obj.properties._XSI_TYPE in cls.match_on:
            hash_value = ObjectHash.get_hash(obj, cls.match_on, cls.case_sensitive)
            if hash_value:
                if hash_value not in lookup_table:
                    lookup_table[hash_value] = SimilarObjectCluster()
                lookup_table[hash_value].add_object(obj, bundle)

    @classmethod
    def get_sources(cls, lookup_table, obj_hash):
        val = []
        for obj_dict_list in lookup_table[obj_hash].values():
            if not obj_dict_list[0] in val: 
                val.append(obj_dict_list[0]['ownerBundle'])
        return val

class ObjectHash(object):
    @classmethod
    def get_hash(cls, obj, match_on, case_sensitive):
        cls.match_on = match_on
        cls.case_sensitive = case_sensitive
        hash_val = ''
        
        for typed_field in obj.properties._get_vars():
            # Make sure the typed field is comparable
            if typed_field.comparable:
                # Check if we're dealing with a nested element that we want to compare
                nested_element = cls.is_nested_match(str(typed_field), cls.match_on[obj.properties._XSI_TYPE])
                # Handle the normal, non-nested case
                if not nested_element and str(typed_field) in cls.match_on[obj.properties._XSI_TYPE]:
                    hash_val = cls.get_val(obj, typed_field, hash_val)
                # Handle the nested case
                elif nested_element:
                   split_nested_element = nested_element.split('.')
                   hash_val = cls.get_val(obj, typed_field, hash_val, split_nested_element[1:])
        if not cls.case_sensitive:
            return hash_val.lower()
        else:
            return hash_val

    @classmethod
    def get_val(cls, obj, typed_field, hash_val, nested_elements = None):
        if not nested_elements:
            val = getattr(obj.properties, str(typed_field))

            if val is not None:
                hash_val += str(typed_field) + ":" + str(val) + " "
        else:
            if len(nested_elements) == 1:
                val = getattr(obj.properties, str(typed_field))
                if val is not None:
                    hash_val += str(typed_field) + ":"
                    if isinstance(val, collections.MutableSequence):
                        for list_item in val:
                            if '/' in str(nested_elements[0]):
                                hash_val += '['
                                split_names = nested_elements[0].split('/')
                                for name in split_names:
                                    name_val = getattr(list_item, name)
                                    if name_val :  hash_val += name + ':' + str(name_val) + ','
                                hash_val = hash_val.rstrip(',')
                                hash_val += ']'
                            else:
                                hash_val += '[' + str(nested_elements[0]) + ':' +  str(getattr(list_item, str(nested_elements[0]))) + ']'
                    else:
                        hash_val += str(getattr(val, nested_elements[0]))
        return hash_val

    @classmethod
    def is_nested_match(cls, typed_field_name, match_on_list):
        for matching_property in match_on_list:
            if '.' in matching_property and typed_field_name in matching_property:
                return matching_property
        return False