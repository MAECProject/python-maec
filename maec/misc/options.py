class ScriptOptions(object):
    """Defines configurable options for MAEC scripts and utilities.

    Attributes:
        deduplicate_bundles: If ``True``, the script will deduplicate all
            Objects in all Bundles (either as standalone entities or embedded 
            in Malware Subjects) before returning or writing out the MAEC document.
            Default value is ``False``.
        dereference_bundles: If ``True``, the script will deference all
            Objects in all Bundles (either as standalone entities or embedded 
            in Malware Subjects) before returning or writing out the MAEC document.
            Default value is ``False``.
        normalize_bundles: If ``True``, the script will normalize all
            Objects in all Bundles (either as standalone entities or embedded 
            in Malware Subjects) before returning or writing out the MAEC document.
            Default value is ``False``.           

    """
    def __init__(self):
        self.deduplicate_bundles = False
        self.dereference_bundles = False
        self.normalize_bundles = False
        
    def to_dict(self):
        return {
            "deduplicate_bundles": self.deduplicate_bundles,
            "dereference_bundles": self.dereference_bundles,
            "normalize_bundles": self.normalize_bundles
        }
