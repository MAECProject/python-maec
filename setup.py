from setuptools import setup, find_packages

setup(
    name="maec",
    version="3.0.0b1",
    author="MAEC Project",
    author_email="maec@mitre.org",
    description="An API for parsing and creating MAEC content.",
    url="http://maec.mitre.org",
    packages=find_packages(),
    install_requires=['lxml>=2.3','cybox>=1.0.0b3']
)
