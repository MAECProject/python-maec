import os

import maec

project = u'python-maec'
copyright = u'2014, The MITRE Corporation'
version = maec.__version__
release = version

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.ifconfig',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
]

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

rst_prolog = """
**Version**: {0}
""".format(release)

exclude_patterns = [
    '_build',
    'api_vs_bindings/*_snippet.rst',
]

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
if not on_rtd:
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
else:
    html_theme = 'default'

latex_elements = {}
latex_documents = [
    ('index', 'python-maec.tex', u'python-maec Documentation',
     u'The MITRE Corporation', 'manual'),
]
