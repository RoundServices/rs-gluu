# rs-gluu is available under the MIT License. https://github.com/RoundServices/rs-gluu/
# Copyright (c) 2022, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

from setuptools import setup

setup(
    name='rs-gluu',
    version='1.0.0',
    description='Python utilities for Gluu',
    url='git@github.com:RoundServices/rs-gluu.git',
    author='Round Services',
    author_email='ggallard@roundservices.biz',
    license='MIT License',
    install_requires=['python-ldap', 'ldif', 'pyDes', 'rs-utils'],
    packages=['rs.gluu'],
    zip_safe=False,
    python_requires='>=3.0'
)
