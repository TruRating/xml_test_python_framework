from setuptools import setup

setup(name='xml_test_framework',
      version='0.1',
      description='framework for test TruRating tools with an http interface',
      author='Sam Bell',
      packages=['xml_test_framework'],
      install_requires=[
          'pyDes',
          'requests',
          'unittest-xml-reporting'
          ],
      include_package_data=True,
      zip_safe=False)
