#!/usr/bin/env python

# Copyright (c) 2018 - The MITRE Corporation
# For license information, see the LICENSE.txt file

from os.path import abspath, dirname, join


from setuptools import setup, find_packages

BASE_DIR = dirname(abspath(__file__))
VERSION_FILE = join(BASE_DIR, 'maec', 'version.py')

def get_version():
    with open(VERSION_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


with open('README.rst', encoding='utf-8') as f:
    readme = f.read()


install_requires = [
    'lxml>=2.2.3',
    'mixbox>=0.0.13',
    'cybox>=2.1.0.13.dev1,<2.1.1.0',
]

extras_require = {
    'docs': [
        'Sphinx',
        'sphinx_rtd_theme',
    ],
    'test': [
        'nose',
        'tox',
    ],
}

setup(
    name="maec",
    version=get_version(),
    author="MAEC Project",
    author_email="maec@mitre.org",
    description="An API for parsing and creating MAEC content.",
    long_description=readme,
    url="http://maec.mitre.org",
    packages=find_packages(),
    install_requires=install_requires,
    extras_require=extras_require,
    classifiers=[
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ]
)
