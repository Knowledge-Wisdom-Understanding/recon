#!/usr/bin/env python3

from setuptools import setup

setup(name='autorecon',
      version='4.0.1',
      description='Automatic Recon Tool',
      classifiers='Development Status :: 2 - Beta',
      keywords='autorecon recon auto-recon og-autorecon autorecon-og',
      url='https://github.com/Knowledge-Wisdom-Understanding/recon',
      author='MrPmillz',
      author_email='wildstyleburner@protonmail.com',
      license='MIT',
      packages=['autorecon', 'autorecon.lib', 'autorecon.utils'],
      include_package_data=True,
      install_requires=['sty', 'tqdm', 'PyYAML', 'wfuzz', 'requests', 'python_hosts', 'psutil', 'python_libnmap',
                        'beautifulsoup4', 'termcolor', 'xmltodict', 'pyasn1', 'python-ldap', 'impacket', 'shodan', 'pycurl'],
      entry_points={'console_scripts': ['autorecon=autorecon.__main__:main']})
