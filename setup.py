"""
 Setup
"""

from setuptools import find_packages, setup

VERSION = "1.1.8"

install_requires = [
    "setuptools>=41.6.0",
    "wheel>=0.30",
    "pyzmq>=25",
    "zmq",
    "pyyaml>=6",
    "dnslib",
    "ipaddress",
    "pyjson>=1.4",
    'urllib3==1.26.6;python_version>="3.8" and python_version<"3.11"',
    "requests",
    "apscheduler==3.10.4",
]

setup(
    name="dns-iot-vct",
    version=VERSION,
    description="DNS-IOT-VCT returns for a base domain and subdomain a parsed local ip",
    url="https://github.com/v-odoo-testing/dns-iot-vct",
    author="Danny Goossen",
    author_email="danny@v-consulting.biz",
    license="MIT",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    scripts=["dns_iot/dns_iot.py"],
    data_files=[
        (
            "dns-iot-vct-post-install",
            ["etc/systemd/system/dns-iot.service", "etc/dns-iot/dns-iot-config.yaml"],
        )
    ],
    test_suite="tests",
)
