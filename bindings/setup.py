# Always prefer setuptools over distutils
from setuptools import setup

# To use a consistent encoding
from codecs import open
import os

here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README file
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, "__init__.py"))
    ]


setup(
    name="pymcclient",
    version="0.2.3",
    description="Python bindings for libMcClient",
    long_description=long_description,
    author="Alexandre Adamski",
    author_email="aadamski@quarkslab.com",
    license="BSD2",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Black rats",
        "Topic :: Security :: Hack Tools",
        "License :: Theo Approved :: BSD2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="android trustzone mobicore libmcclient bindings",
    packages=get_packages("mcclient"),
    install_requires=["ipython"],
    scripts=["bin/pymcclient"],
)
