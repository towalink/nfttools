import os
import setuptools


with open('README.md', 'r') as f:
    long_description = f.read()

setup_kwargs = {
    'name': 'nfttools',
    'version': '0.1.2',
    'author': 'Dirk Henrici',
    'author_email': 'towalink.nfttools@henrici.name',
    'description': 'help interacting with nftables',
    'long_description': long_description,
    'long_description_content_type': 'text/markdown',
    'url': 'https://www.github.com/towalink/nfttools',
    'packages': setuptools.find_namespace_packages('src'),
    'package_dir': {'': 'src'},
    'extras_require': {
        'nftables': ['pip-nftables',
                     'jsonschema',
                    ],
    }, 
    'classifiers': [
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology'
    ],
    'python_requires': '>=3.7',
    'keywords': 'nftables validation parsing',
    'project_urls': {
        'Repository': 'https://www.github.com/towalink/nfttools',
        'PyPi': 'https://pypi.org/project/nfttools/'
    },
}


if __name__ == '__main__':
    setuptools.setup(**setup_kwargs)
