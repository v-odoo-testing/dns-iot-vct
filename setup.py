import os
import sys

from setuptools import find_packages
from setuptools import setup

version = '1.0.0'

install_requires = [
    'pyzmq>=25',
    'pyyaml',
    'setuptools>=41.6.0',
]

setup(
    name='dns-iot-vct',
    version=version,
    description="DNS-IOT-VCT returns for a base domain and subdomain a parsed local ip",
    url='https://github.com/v-odoo-testing/certbot_dns_vctdns',
    author="Danny Goossen",
    author_email='danny@v-consulting.biz',
    license='MIT',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,

)
