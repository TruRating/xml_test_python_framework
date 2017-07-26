import unittest
import os
import xml.etree.ElementTree as ET
#import lxml
import requests
import socket
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import threading
import Queue
import json
import time
import collections
import itertools
from hashlib import sha256
from pyDes import triple_des, ECB,PAD_PKCS5
import base64
import array
import ConfigParser
import uuid
import fnmatch
import logging
import sys

def updateSessionId() :
    config = ConfigParser.ConfigParser()
    
    value = 0
    config_file = os.path.join(test_folder,'test_config')
    if os.path.isfile(config_file) :
        config.readfp(open(config_file))
        value = config.getint('IDs',"Session")
    else :
        config.add_section('IDs')

    config.set('IDs','Session',str(value + 1))
        
    with open(config_file, 'wb') as configfile:
            config.write(configfile)
    return value

def getSessionId() :
    config = ConfigParser.ConfigParser()
    
    value = 0
    config_file = os.path.join(test_folder,'test_config')
    if os.path.isfile(config_file) :
        config.readfp(open(config_file))
        value = config.getint('IDs',"Session")

    return value

activationCode = '8936478905968313'
class SimpleHandler(BaseHTTPRequestHandler):

    def do_HEAD(self):
        print str(self.headers)

    def generateMac(self, content):
        hex_content = sha256(content).digest()
        return sha256(content).digest()

    def des_acb3_encrypt(self, content,mac_key):
        k = triple_des(mac_key,ECB,pad=None, padmode=PAD_PKCS5)
        return k.encrypt(content)
        
    def do_POST(self):
  
        data = self.server.exchange_queue.get(block = False)
        path,storage_name = data;
                
        response_file = open(path)
        response_content = response_file.read()

        headers, body = response_content.split("\n\n")
        iterator = iter(headers.split("\n"))
        status_line = next(iterator)
        http,code,status = status_line.split(" ")
        self.send_response(int(code))
        
        client_id ='0'
        if 'x-tru-api-client-id' in self.headers.dict:
            client_id = self.headers.dict['x-tru-api-client-id']

        mac_key = "123456789012345678901234".encode("utf-8")
        if client_id != '0' :
            mac_key = '{0}{1}'.format(client_id.rjust(8,'0'),activationCode)

        if body :
            response_json = json.loads(body)        
            if 'activationKey' in response_json :
                response_json['activationKey'] = activationCode

            body = json.dumps(response_json)
        mac = self.generateMac(body)
        encrypted_mac = self.des_acb3_encrypt(mac,mac_key)

        data = array.array('B',encrypted_mac)
        hexstring = ''.join(format(n,'02X') for n in data)
        for header in iterator:
            key, value = header.split(":",1)
            if key == 'x-tru-api-mac' :
                self.send_header(key,hexstring)
            else :
                self.send_header(key,value)
        self.end_headers()       
        self.wfile.write(body)

        #store the received values at the end once we have sent the response.
        global storage
        global mutex
        try :
            mutex.acquire()
            storage[storage_name + '_headers'] = self.headers.dict
            storage[storage_name] = self.rfile.read(int(self.headers['Content-Length']))
        finally:
            mutex.release()
   
            

def get_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, name))]

def get_value(in_value):
    list = in_value.split(':')
    if len(list) == 2:
        data_type, value = list
        if data_type=='path':
            file_path = value
            if not os.path.isabs(file_path) :
                file_path = os.path.abspath(file_path)
            out_value = open(file_path).read()
        else:
            out_value = value
    else:
        out_value = in_value
    if out_value == '$session_id':
        out_value = str(getSessionId())
    elif out_value == '$update_session_id':
        out_value = str(updateSessionId())
    elif out_value == '$uuid':
        out_value = str(uuid.uuid4())
    return out_value

class AlterAttributeHandler :
    def __init__(self,xml_root,xpath, attribute, value ):
        self.xml_root = xml_root
        self.xpath = xpath
        self.attribute = attribute
        self.value = value
    
    def run(self):
        element = self.xml_root.find(self.xpath)
        element.attrib[self.attribute] = get_value(self.value) 

class RawRequestHandler :

    def __init__(self,element_node, path, timeout = 10, data_name='default',server="localhost",port="9618"):
        self.element_node = element_node
        if not os.path.isabs(path) :
            self.path = os.path.abspath(path)
        else :
            self.path = path
        self.timeout = timeout
        self.data_name = data_name
        self.server = server
        self.port = port

    def run(self):
        print "run RawRequestHandler"
        log= logging.getLogger( "SomeTest.testSomething" )
        log.debug( "run RawRequestHandler" )
        request_file = open(self.path)
        tree = ET.parse(request_file)

        iterator = self.element_node.iter()
        iterator.next()
        for element in iterator :
            xml_editors[element.tag](tree, element)

        request_xml = """<?xml version="1.0"?>{0}""".format(ET.tostring(tree.getroot()))
        buffer_size = 1024*1024
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(int(self.timeout))
        s.connect((self.server,int(self.port)))
        log= logging.getLogger( "SomeTest.testSomething" )
        log.debug( "send data %s", request_xml )
        s.send(request_xml)
        data = s.recv(buffer_size)
        log.debug( "recv data %s", data )

        global storage
        global mutex
        try:
            mutex.acquire()
            storage[self.data_name] = data 
        finally:
            mutex.release()


class ServiceRequestHandler :

    def __init__(self,element_node, path, timeout = 10, data_name='default',url="http://localhost:31415/api/servicemessage"):
        self.element_node = element_node
        if not os.path.isabs(path) :
            self.path = os.path.abspath(path)
        else :
            self.path = path
        self.timeout = timeout
        self.data_name = data_name
        self.url = url
        
    
    def run(self):
        request_file = open(self.path)
        tree = ET.parse(request_file)
        
        iterator = self.element_node.iter()
        iterator.next()
        for element in iterator :
            xml_editors[element.tag](tree, element)

        request_xml = ET.tostring(tree.getroot())
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(self.url,data=request_xml,headers=headers, timeout=self.timeout)
        
        global storage
        global mutex
        try:
            mutex.acquire()
            storage[self.data_name + '_status_code'] = response.status_code
            if response.status_code == 200 :
                storage[self.data_name] = response.content
            elif self.data_name in storage:
                del storage[self.data_name]
        finally:
            mutex.release()


class StartHostHandler :
    def __init__(self, port, host_name, server_address="localhost" ):
        self.port = int(port)
        self.server_address = server_address     
        self.host_name = host_name   
    
    def run(self):
        global host_storage
        server_address = (self.server_address, self.port)
        host_storage[self.host_name] = HTTPServer(server_address, SimpleHandler) 
        host_storage[self.host_name].exchange_queue = Queue.Queue()
        t = threading.Thread(target=host_storage[self.host_name].serve_forever)
        t.daemon = True
        t.start()

class StopHostHandler :
    def __init__(self,host_name="default_host" ):   
        self.host_name = host_name
    
    def run(self):
        global host_storage
        host_storage[self.host_name].shutdown()
        
            
class HostRequestHandler :

    def __init__(self, path, host_name, data_name='default', timeout = 10):
        if not os.path.isabs(path) :
            self.path = os.path.abspath(path)
        else :
            self.path = path
        self.timeout = timeout
        self.data_name = data_name
        self.host_name = host_name
        
    def run(self):
        global host_storage
        global storage
        global mutex
        try:
            mutex.acquire()
            if self.data_name in storage :
                del storage[self.data_name]
            host_storage[self.host_name].exchange_queue.put([self.path,self.data_name])
        finally:
            mutex.release()

def compare_collection(left_collection,right_collection):
    for l,r in zip(left_collection,right_collection):
        if isinstance(l,dict) and isinstance(r,dict) :
            success, error_message = compare_dict(l,r)
            if not success :
                return False, error_message
        elif not isinstance(l, basestring) and isinstance(l,collections.Iterable) and isinstance(r,collections.Iterable) :
            success, error_message = compare_collection(l,r)
            if not success:
                return False, error_message
        elif l != r and v1 != "$any" and v2 != '$any':
            return False, '{0} != {1}'.format(str(l),str(r))
    return True, "Success"

def compare_dict(left_dict, right_dict):
        for (k1,v1),(k2,v2) in zip(left_dict.items(),right_dict.items()):
            if k1 == k2 :
                if isinstance(v1,dict) and isinstance(v2,dict) :
                    success, error_message = compare_dict(v1,v2)
                    if not success:
                        return False, error_message
                elif not isinstance(v1, basestring) and isinstance(v1,collections.Iterable) and isinstance(v2,collections.Iterable) :
                    success, error_message = compare_collection(v1,v2)
                    if not success:
                        return False, error_message
                elif v1 != v2 and v1 != "$any" and v2 != '$any':
                    return False, '{0}:{1} != {2}:{3}'.format(str(k1),str(v1),str(k2),str(v2))
            else:
                return False, '{0}:{1} != {2}:{3}'.format(str(k1),str(v1),str(k2),str(v2))
        return True, "Success"

def wait_for_value(data_name,wait_for_value):
    a = 0
    global mutex
    global storage
    while a < int(wait_for_value) : 
        try:
            mutex.acquire()
            if data_name in storage :
                break
        finally:
            mutex.release()
        time.sleep(1)   
        a += 1
    if data_name not in storage :
        raise RuntimeError("""Value '{1}' not available""".format(data_name))

class DynamicClassBase(unittest.TestCase):
    
    assert_id = 0

    def get_value(self,value,wait_for_value, description = None):
        self.assert_id += 1
        string_test_id = str(self.assert_id)
        if description is not None :
            string_test_id = description

        a = 0
        global mutex
        global storage            
        while a < int(wait_for_value) : 
            try:
                mutex.acquire()
                if value in storage :
                    break
            finally:
                mutex.release()
            time.sleep(1)   
            a += 1
        self.assertTrue(value in storage, """Value '{1}' not available. Assert {0}""".format(string_test_id,value))
        return_value = storage[value]

        return string_test_id, return_value

    def assertXmlEqual(self,data_name,expected,description = None, wait_for_value = 0):
        
        string_test_id,found_value = self.get_value(data_name,wait_for_value,description)
        
        response_root = ET.fromstring(found_value)

        expected_value = get_value(expected)
        expected_root = ET.fromstring(expected_value)

        response_it = response_root.iter()
        expected_it = expected_root.iter()
        for expected,actual in itertools.izip_longest(expected_it,response_it):
            if expected is None and actual is not None:
                 element_error = """mismatched elements, did not expect <{0}>""".format(actual.tag)
                 self.assertTrue(False,'XML comparison failed {0}. Assert {1}'.format(element_error, string_test_id));
            if expected is not None and actual is None:
                 element_error = """mismatched elements, expected <{0}>""".format(expected.tag)
                 self.assertTrue(False,'XML comparison failed {0}. Assert {1}'.format(element_error, string_test_id));
            if expected.tag != actual.tag :
                element_error = 'element {0} != {1}'.format(expected.tag,actual.tag)
                self.assertTrue(False,'XML comparison failed {0}. Assert {1}'.format(element_error, string_test_id));
            success,error_message = compare_dict(expected.attrib,actual.attrib)
            if not success :
                element_error = 'For element {0} attribute does not match {1}'.format(expected.tag,error_message)
                self.assertTrue(success, 'XML comparison failed {0}. Assert {1}'.format(element_error, string_test_id))
            

    def assertJsonEqual(self,data_name,expected,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name,wait_for_value,description)

        response_json = json.loads(found_value)
        expected_value = get_value(expected)
        expected_json = json.loads(expected_value)
        success,error_message = compare_dict(expected_json,response_json)
        self.assertTrue(success, 'JSON comparison failed {0}. {1}'.format(error_message, string_test_id))

    def assertHttpHeaderEqual(self,data_name,header,expected,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name+'_headers',wait_for_value,description)

        header_value = found_value[header]
        self.assertEquals(header_value,get_value(expected), '{1} != {2}. Assert {0}'.format(string_test_id,header_value,get_value(expected)))

    def assertStatusCodeEqual(self,data_name,expected,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name+'_status_code',wait_for_value,description)

        self.assertEquals(found_value,int(get_value(expected)), '{1} != {2}. Assert  {0}'.format(string_test_id,found_value,int(get_value(expected))))

    def assertHasElement(self,data_name,xpath,expected=None,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name,wait_for_value,description)

        response_root = ET.fromstring(found_value)
        element = response_root.find(xpath)
        self.assertFalse(element is None, 'Element {1} not found. Assert  {0}'.format(string_test_id,xpath))
        if expected is not None :
            self.assertEqual(element.tag, get_value(expected) , '{1} != {2}. Assert  {0}'.format(string_test_id,element.tag,get_value(expected)))

    def assertElementValueEqual(self,data_name,xpath,expected,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name,wait_for_value,description)

        response_root = ET.fromstring(found_value)
        element = response_root.find(xpath)
        self.assertFalse(element is None, 'Element {1} not found. Assert  {0}'.format(string_test_id,xpath))
        expected = get_value(expected)
        self.assertEqual(element.text, expected , '{1} != {2}. Assert  {0}'.format(string_test_id,element.text,expected))

    def assertAttributeValueEqual(self,data_name,xpath,attribute,expected,description=None, wait_for_value = 0):
        string_test_id,found_value = self.get_value(data_name,wait_for_value,description)

        response_root = ET.fromstring(found_value)
        element = response_root.find(xpath)
        self.assertFalse(element is None, 'Element {1} not found. Assert  {0}'.format(string_test_id,xpath))
        self.assertTrue(attribute in element.attrib, 'Attribute {1} not found in element {2}. Assert  {0}'.format(string_test_id,attribute, xpath))
        expected = get_value(expected)
        self.assertEqual(element.attrib[attribute], expected , '{1} != {2}. Assert  {0}'.format(string_test_id,element.attrib[attribute],expected))
        
mutex = threading.Lock()
storage = {}
commands={}
#commands
commands['start_host'] = lambda x,y: StartHostHandler(**y.attrib).run()
commands['stop_host'] = lambda x,y: StopHostHandler(**y.attrib).run()
commands['service_request'] = lambda x,y: ServiceRequestHandler(y,**y.attrib).run()
commands['raw_request'] = lambda x,y: RawRequestHandler(y,**y.attrib).run()
commands['host_request'] = lambda x,y: HostRequestHandler(**y.attrib).run()
commands['description'] = lambda x,y: None
commands['wait_for_response'] = lambda x,y: wait_for_value(**y.attrib)
#asserts
commands['assert_xml_equal'] = lambda x,y: x.assertXmlEqual(**y.attrib)
commands['assert_json_equal'] = lambda x,y: x.assertJsonEqual(**y.attrib)
commands['assert_http_header_equal'] = lambda x,y: x.assertHttpHeaderEqual(**y.attrib)
commands['assert_status_code_equal'] = lambda x,y: x.assertStatusCodeEqual(**y.attrib)
commands['assert_has_element'] = lambda x,y: x.assertHasElement(**y.attrib)
commands['assert_element_value_equal'] = lambda x,y: x.assertElementValueEqual(**y.attrib)
commands['assert_attribute_value_equal'] = lambda x,y: x.assertAttributeValueEqual(**y.attrib)


xml_editors={}
xml_editors['alter_attribute'] = lambda xml,y: AlterAttributeHandler(xml,**y.attrib).run()


def make_check_test(xml_path):
    def test(self):  
    #    schema_doc = ET.parse("TestCase.xsd")
       # xmlschema = ET.XMLSchema(schema_doc)
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)

      #  xmlschema.validate(tree)
        root = tree.getroot()
            
        try:
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    log= logging.getLogger( "SomeTest.testSomething" )
                    log.debug( "run command %s", element.tag )
                    commands[element.tag](self, element)
        finally:
            cleanup_root = tree.getroot().find('cleanup')
            if cleanup_root is not None :
                iterator = cleanup_root.iter()
                iterator.next()
                for element in iterator :
                    if element.tag in commands :
                        commands[element.tag](self, element)
    return test

def make_test_setup(xml_path):
    def setup(self):  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](self, element)

    return setup

def make_test_teardown(xml_path):
    def teardown(self):  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()

        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](self, element)

    return teardown

def make_class_setup(xml_path):
    def setup(cls):  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](self, element)

    return setup


def make_class_teardown(xml_path):
    def teardown(cls):  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()

        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](self, element)

    return teardown


def make_module_setup(xml_path):
    def setup():  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()

        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](None, element)

    return setup

def make_module_teardown(xml_path):
    def teardown():  
        os.chdir(os.path.dirname(xml_path))
        tree = ET.parse(xml_path)
        root = tree.getroot()

        if root is not None :
            iterator = root.iter()
            iterator.next()
            for element in iterator :
                if element.tag in commands :
                    commands[element.tag](None, element)

    return teardown

test_folder = ''
filter_tests = False
test_names = []
host_storage = {}

def load_tests(loader, tests, pattern):
    logging.basicConfig( stream=sys.stderr )
    log= logging.getLogger( "SomeTest.testSomething" )
    log.setLevel( logging.DEBUG )
    global test_folder
    log.debug( "begin logging %s", test_folder )
    test_folder = os.path.abspath(test_folder)
    sub_dirs = get_subdirectories(test_folder)
    allTests = unittest.TestSuite()
     
    for dir in sub_dirs :
        temp_dir = os.path.join(test_folder,dir)
        for subdirs,dirs,files in os.walk(temp_dir):
            test_dict = {}         

            for xml_file in files:
                base_name = os.path.splitext(xml_file)[0]
                if base_name == 'setup' :
                    test_setup = make_test_setup(os.path.join(temp_dir,xml_file))
                    test_dict['setUp'] = test_setup    
                elif base_name == 'teardown':
                    test_teardown = make_test_teardown(os.path.join(temp_dir,xml_file))
                    test_dict['tearDown'] = test_teardown
                if base_name == 'initialSetup' :
                    test_setup = make_test_setup(os.path.join(temp_dir,xml_file))
                    test_dict['setUpClass'] = classmethod(test_setup)    
                elif base_name == 'finalTeardown':
                    test_teardown = make_test_teardown(os.path.join(temp_dir,xml_file))
                    test_dict['tearDownClass'] = classmethod(test_teardown)
                else :
                    test_func = make_check_test(os.path.join(temp_dir,xml_file))
                    func_test_name = 'test_{0}'.format(base_name)
                    test_dict[func_test_name] = test_func
                
            class_name = '{0}'.format(dir)
            test_case = type(class_name,
                        (DynamicClassBase,),
                        test_dict)
            globals()[test_case.__name__] = test_case

    for content in os.listdir(test_folder):
        if os.path.isfile(os.path.join(test_folder,content)):
            base_name = os.path.splitext(content)[0]
            if base_name == 'setup' :
                test_setup = make_module_setup(os.path.join(test_folder,content))
                globals()['setUpModule'] = test_setup
            elif base_name == 'teardown':
                test_teardown = make_module_teardown(os.path.join(test_folder,content))
                globals()['tearDownModule'] = test_teardown

    if filter_tests:
        for pattern in test_names:
            suite = unittest.TestSuite()
            if pattern.find('*') >= 0:
                for dir in sub_dirs:
                    if fnmatch.fnmatch(dir, pattern):
                        tests = loader.loadTestsFromName('xml_test_framework.xml_tests.'+dir)
                        suite.addTest(tests)
            else :
                tests = loader.loadTestsFromName('xml_test_framework.xml_tests.'+pattern)
                suite.addTest(tests)
            allTests.addTest(suite)
    else:
        for dir in sub_dirs:
            allTests.addTest(loader.loadTestsFromName('xml_test_framework.xml_tests.' + dir))
    return allTests
