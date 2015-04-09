# Copyright (c) 2015, The MITRE Corporation
# All rights reserved
"""MAEC utility methods"""


def flip_dict(d):
    """Returns a copy of the input dictionary `d` where the values of `d`
    become the keys and the keys become the values.

    Note:
        This does not even attempt to address key collisions.

    Args:
        d: A dictionary

    """
    return dict((v,k) for k, v in d.iteritems())


# Namespace flattening
import maec
from .nsparser import maecMETA
from .idgen import *
from .parser import EntityParser
from .comparator import (ObjectHash, BundleComparator, SimilarObjectCluster,
                         ComparisonResult)
from .deduplicator import BundleDeduplicator
