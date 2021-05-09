from setuptools import find_packages, setup

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='envcrypto',
    version='0.2.0',
    description='A safe way to store environmental variables.',
    long_description_content_type='text/markdown',
    long_description=long_description,
    author='Fufu',
    author_email='fufuokok@gmail.com',
    url='https://github.com/fufuok/envcrypto',
    license='MIT',
    packages=find_packages(exclude=['tmp']),
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    python_requires='>=3.6',
    install_requires=['pycryptodome>=3.9.8'],
)
