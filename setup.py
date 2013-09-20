import maec

from setuptools import setup, find_packages

setup(
    name="maec",
    version=maec.__version__,
    author="MAEC Project",
    author_email="maec@mitre.org",
    description="An API for parsing and creating MAEC content.",
    url="http://maec.mitre.org",
    packages=find_packages(),
    install_requires=['lxml>=2.3','cybox>=2.0.0,<2.0.1']
)
