import unittest
import os
import xmlrunner
import argparse
import sys
import xml_test_framework.xml_tests
    
if __name__ == '__main__':
         
    parser = argparse.ArgumentParser(description='Run Tests',formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p','--path', nargs='?', default='tests',help="Path to test directory")
    parser.add_argument('-r','--report', nargs='?',default='test-reports', help='Directory for report file')
    parser.add_argument('test',type=str, help='List of named tests, can specify module(s)\n\t<folder_name>\nor individual test(s)\n\t<folder_name>.test_<test_name>', nargs='*')
    args = parser.parse_args(sys.argv[1:])

    module = sys.modules['xml_test_framework.xml_tests']
    setattr(module, 'test_folder', args.path)
    if args.test :
        setattr(module,'test_names',args.test)
        setattr(module,'filter_tests',True)
    report_dir = args.report
 
    tests = unittest.TestLoader().loadTestsFromModule(xml_test_framework.xml_tests)
    
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    with open(os.path.join(report_dir,'results.xml'), 'wb') as output:
        testRunner=xmlrunner.XMLTestRunner(output=output)
        testRunner.run(tests) 