from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()


setup(
    name='bc_dock_util',
    version='0.0.1',
    author='caifh',
    author_email='caifh@tianxiaxinyong.com',
    description=(
        'B client docking tianxiaxinyong service sdk util.'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    maintainer='caifh',
    maintainer_email='caifh@tianxiaxinyong.com',
    license='BSD License',
    packages=find_packages(),
    platforms=['all'],
    url='https://www.tianxiaxinyong.com/',
    install_requires=[
        'pycryptodome>=3.5.1',
        'cryptography>=2.3',
        'Requests>=2.19.1'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries'
    ]
)
