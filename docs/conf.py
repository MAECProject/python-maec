import maec

project = u'python-maec'
copyright = u'2014, The MITRE Corporation'
version = maec.__version__
release = version

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.ifconfig',
    'sphinx.ext.intersphinx',
    'sphinxcontrib.napoleon',
]

intersphinx_mapping = {'http://docs.python.org/': None}

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

rst_prolog = """
.. warning::

    This documentation is still a work in progress. If you have any issues or
    questions, please ask on the maec-discussion mailing list or file a bug
    in our `issue tracker`_.

.. _issue tracker: https://github.com/MAECProject/python-maec/issues
"""

exclude_patterns = ['_build']
pygments_style = 'sphinx'

html_theme = 'default'
html_style = '/default.css'
html_static_path = ['_static']
htmlhelp_basename = 'python-maecdoc'

html_theme_options = {
    'codebgcolor': '#EEE',
    'footerbgcolor': '#FFF',
    'footertextcolor': '#114684',
    'headbgcolor': '#E0DBD2',
    'headtextcolor': '#F15A22',
    'headlinkcolor': '#114684',
    'linkcolor': '#706C60',
    'relbarbgcolor': '#114684',
    'relbartextcolor': '#F15A22',
    'sidebarbgcolor': '#FFF',
    'sidebarlinkcolor': '#706C60',
    'sidebartextcolor': '#000',
    'visitedlinkcolor': '#706C60',
}
html_sidebars = {"**": ['localtoc.html', 'relations.html', 'sourcelink.html',
'searchbox.html', 'links.html']}

latex_elements = {}
latex_documents = [
  ('index', 'python-maec.tex', u'python-maec Documentation',
   u'The MITRE Corporation', 'manual'),
]
