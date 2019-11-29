import platform
from setuptools import setup, find_packages
bits, linkage = platform.architecture()
if linkage != 'WindowsPE':
    raise RuntimeError('minhook only support windows')

with open("README.md", "r",encoding='utf-8') as fh:
    long_description = fh.read()
setup(
    name='pyminhook',
    version='0.1',
    url='https://github.com/howmp/pyminhook',
    license='MIT',
    author='howmp',
    author_email='zhaopeiyuan6@gmail.com',
    description='MinHook warp of Python',
    packages=find_packages(),
    package_data={
        'minhook': ['*.dll'],
    },
    long_description=long_description,
    long_description_content_type="text/markdown",
    zip_safe=False,
    python_requires='>=3.7',
)
