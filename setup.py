from distutils.core import setup
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='amzn-associates-api',
    author='Alex Reed',
    author_email='coding.sigma@gmail.com',
    version='0.0.1',
    description='A python API client library used to interact with the Amazon Associates Marketing API.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/areed1192/amzn-associates-api',
    install_requires=[
        'requests>=0.22'
    ],
    packages=find_packages(include=['amzn_associates']),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Financial and Insurance Industry',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3'
    ],
    python_requires='>3.7'
)
