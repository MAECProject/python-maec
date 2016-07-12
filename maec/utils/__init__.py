# Copyright (c) 2015, The MITRE Corporation
# All rights reserved
"""MAEC utility methods"""

from mixbox.vendor.six import iteritems

def flip_dict(d):
    """Returns a copy of the input dictionary `d` where the values of `d`
    become the keys and the keys become the values.

    Note:
        This does not even attempt to address key collisions.

    Args:
        d: A dictionary

    """
    return dict((v,k) for k, v in iteritems(d))

# Namespace flattening
from .parser import EntityParser # noqa
from .comparator import (ObjectHash, BundleComparator, SimilarObjectCluster, # noqa
                         ComparisonResult) # noqa
from .deduplicator import BundleDeduplicator # noqa

#Ensure MAEC namespaces get registered
from .nsparser import *  # noqa 
