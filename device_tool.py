"""
device_tool
-----------
A script to perform some operations on Axis devices.  This script should run
on any standard Python 3 distribution.

Examples:

   1. Get supported events from a device:

      python3 device_tool.py -u root -p pass -c 192.168.1.3 -f GetEventInfo

   2. As 1, but rely on the connection parameters of last eap-install.sh
      invocation (stored in .eap-install.cfg):

      python3 device_tool.py -f GetEventInfo

   3. As 2, but print summary of GetEventInfo instead:

      python3 device_tool.py -f GetEventInfo -d

   4. Get serverreport of several cameras, using credentials from
      .eap-install.cfg on all devices

      python3 device_tool.py -c 192.168.1.3 -c 192.168.1.4 -c 192.168.1.5 -f GetServerReport

   5. See more options, and actual credentials in use:

      python3 device_tool.py -h

   6. Install ACAP (again), start it, wait two minutes, remove it

      python3 device_tool.py -f "UploadAcap(filename=youracap_0_8_5_armv7hf.eap)" -f ListAcaps -f "StartAcap(package=youracap)" -f "Wait(seconds=120)" -f "RemoveAcap(package=youracap)" -f ListAcaps

   7. Retrieve a serverreport every two hours, until Ctrl-C is pressed:

      python3 device_tool.py -f GetServerReport -i 0
"""
import os
import sys
import argparse
import time
import datetime
import re
import json
import socket
from copy import copy
from typing import Optional, Union
import xml.etree.ElementTree as ET
import pprint
import configparser

import collections.abc

import http.cookiejar
import http.client

import urllib.parse
import urllib.error
import urllib.request

GLOBAL_COUNTER = 0

#-------------------------------------------------------------------------------
#
#   Utilities                                                               {{{1
#
#-------------------------------------------------------------------------------

prv_gethostbyname = socket.gethostbyname

def new_gethostbyname(hostname):
   """
   Avoid DNS lookups on hostnames that are already an IP address, so that
   the tool runs properly in DNS-less ad-hoc networks

   Monkeypatch:
   socket.gethostbyname = new_gethostbyname
   """
   try:
      _ = socket.inet_aton(hostname)
      return hostname
   except socket.error:
      res = prv_gethostbyname(hostname)
      return res

socket.gethostbyname = new_gethostbyname

class Denamespacer:
   """
   Helper class to undo tags from their ElementTree internal namespace-representation
   """
   def __init__(self, namespaces):
      self.pattern = re.compile( r'{(.*)}(.*)' )
      self.namespaces = namespaces
      self.reverse_namespaces = {}
      for key, val in namespaces.items():
         self.reverse_namespaces[val] = key

   def append_namespace(self, namespaces):
      self.namespaces.extend(namespaces)
      for key, val in namespaces.items():
         self.reverse_namespaces[val] = key

   def _split_namespace_and_tag(self, elementtree_tag: str):
      """
      """
      if elementtree_tag.startswith('{'):
         m = self.pattern.match(elementtree_tag)
         return m.group(1), m.group(2)
      return None, elementtree_tag

   def tag(self, elementtree_tag: str) -> str:
      """
      """
      namespace, _tag = self._split_namespace_and_tag(elementtree_tag)
      if namespace:
         return f'{self.reverse_namespaces[namespace]}:{_tag}'
      return _tag

class EventtopicDenamespacer(Denamespacer):
   """
   A Denamespacer specifically for Axis eventtopics
   """
   topicfilters = {
      'tns1': 'onvif',
      'tnsaxis': 'axis'
   }

   def tag(self, elementtree_tag: str) -> str:
      namespace, _tag = self._split_namespace_and_tag(elementtree_tag)
      if namespace:
         reverse = self.reverse_namespaces[namespace]
         if reverse in self.topicfilters:
            reverse = self.topicfilters[reverse]
         return f'{reverse}:{_tag}'
      return _tag

def dictify(r: ET, denamespacer: Denamespacer, root=True) -> dict:
   """
   Convert XML string to a dict.
   Credits: https://stackoverflow.com/questions/2148119/

   denamespacing is my own weird addition
   """
   if root:
      return {r.tag : dictify(r, denamespacer, False)}
   d = copy(r.attrib)
   if r.text:
      d["_text"] = r.text
   for x in r.findall("./*"):
      dns_tag = denamespacer.tag(x.tag)
      if dns_tag not in d:
         d[dns_tag] = []
      d[dns_tag].append(dictify(x, denamespacer, False))
   return d

def parse_call(func_call):
   """
   This one splits a command-line string into a function-name and keyword
   arguments list that can be passed to the function implementing
   'function-name'
   """
   part1 = func_call.strip().split( '(' )
   kwargs = {}
   if len(part1) > 1 and len(part1[1]) > 1:
      args = part1[1][:-1].split(',')
      for a in args:
         x = a.split('=',1)
         kwargs[ x[0] ] = x[1]
   return part1[0], kwargs

# In-place ElementTree prettyprint formatter
# Credits: http://effbot.oRg/zone/element-lib.htm#prettyprint

def xml_indent(elem, level = 0):
   i = "\n" + level * "  "
   if len(elem):
      if not elem.text or not elem.text.strip():
         elem.text = i + "  "
      if not elem.tail or not elem.tail.strip():
         elem.tail = i
      for sub_el in elem:
         xml_indent(sub_el, level+1)
      if not elem.tail or not elem.tail.strip():
         elem.tail = i
   else:
      if level and (not elem.tail or not elem.tail.strip()):
         elem.tail = i

def write_data(filename, content):
   """
   Save content in file filename
   """
   with open(filename, 'wb') as f:
      f.write(content)

#-------------------------------------------------------------------------------
#
#   Web access                                                              {{{1
#
#-------------------------------------------------------------------------------

DEBUG_HTTP = 0

# Example proxy: 'http://username:password@proxy.yourdomain:3128'

class WebAccess:
   """
   A urllib based http-client. There are no real advantages to the urllib
   approach other than to keep this script free of non-standard
   dependencies, like requests
   """
   def __init__(self, site_url, temp_dir = '.', proxy = None, context = None):
      self.site_url = site_url
      self.pwd_mngr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
      self.cj = http.cookiejar.LWPCookieJar()
      self.cookie_file = temp_dir + os.sep + 'cookie.lwp'
      self.h = []
      self.h.append(urllib.request.HTTPHandler(debuglevel = DEBUG_HTTP))
      self.h.append(urllib.request.HTTPSHandler(debuglevel = DEBUG_HTTP, context = context))
      self.h.append(urllib.request.HTTPDigestAuthHandler(self.pwd_mngr))
      self.h.append(urllib.request.HTTPBasicAuthHandler(self.pwd_mngr))
      if proxy:
         self.h.append(urllib.request.ProxyHandler({'http': proxy}))
      self.opener = urllib.request.build_opener(*self.h)
      self.context = context

   def __del__(self):
      pass

   def add_credentials(self, usr, passw, url = None):
      if url is None:
         url = self.site_url
      self.pwd_mngr.add_password(None, url, usr, passw )

   def get(self, url_str, extra_headers = {}):
      url = self.site_url + url_str
      req = urllib.request.Request(url = url, headers = extra_headers)
      response = self.opener.open(req)
      return response

   def post(self, url_str, params, extra_headers = None):
      url = self.site_url + url_str
      if isinstance(params, str):
         r = urllib.request.Request(url, params.encode('utf-8'), headers = extra_headers)
      else:
         r = urllib.request.Request(url, params, headers = extra_headers)
      response = self.opener.open(r)
      return response

   def post_file(self, url_str, filename, content_type='text/plain', \
                 uploadname=None, extra_headers = None):
      """
      Upload file plain ascii file 'filename' to 'url_str', pretending it to
      be file 'uploadname'. If no uploadname specified use original filename
      """
      my_boundary = b'-------------------------114782935826962'
      url = self.site_url + url_str
      if uploadname is None:
         uploadname = os.path.basename(filename)
      upload_prefix = \
          f'Content-Disposition: form-data; name=\"fileName\"; filename=\"{uploadname}\"\r\nContent-Type: {content_type}\r\n\r\n'.encode()
      upload_postfix = b'\r\n'
      with open(filename, 'rb') as f:
         upload_text = b'--' + my_boundary + b'\r\n' + upload_prefix + f.read() + upload_postfix + b'--' + my_boundary + b'--\r\n'
      h = extra_headers if isinstance(extra_headers, dict) else {}
      h['Content-Type'] = b'multipart/form-data; boundary=' + my_boundary
      h['Content-Length'] = f'{len(upload_text)}'.encode()
      r = urllib.request.Request(url, upload_text, headers = h)
      response = self.opener.open(r)
      return response

#-------------------------------------------------------------------------------
#
#   VAPIX Client                                                            {{{1
#
#-------------------------------------------------------------------------------

# See: https://stackoverflow.com/questions/55921412

MINIMAL_VAPIX_NAMESPACES = {
   'SOAP-ENV': 'http://www.w3.org/2003/05/soap-envelope',
   'aev': 'http://www.axis.com/vapix/ws/event1',
   'wstop': 'http://docs.oasis-open.org/wsn/t-1',
   'tns1': 'http://www.onvif.org/ver10/topics',
   'tnsaxis': 'http://www.axis.com/2009/event/topics' ,
   'act':	'http://www.axis.com/vapix/ws/action1',
   'entry': 'http://www.axis.com/vapix/ws/entry'
}

LIST_FEATUREFLAGS = """
{
  "apiVersion": "1.0",
  "context": "my context",
  "method": "listAll"
}
"""

class VapixClient:
   """
   This class implements several VAPIX requests. Note that since VAPIX-inception
   in the late '90s several types of interfaces were added:

     1. The original plain old GET's with parameters in the url
     2. VAPIX webservices, with authentication in HTTP header, not in
        SOAP-envelope like ONVIF has
     3. Simple GET requests, webservice-like response
     4. JSON based functions
   """
   def __init__(self, w, dump_raw_bytes = False):
      self.w = w
      self.debug = dump_raw_bytes
      # SOAP-related
      for key, val in MINIMAL_VAPIX_NAMESPACES.items():
         ET.register_namespace(key, val)
      # Used for converting vapix namespaces to topicfilter namespaces
      self.denamespacer = EventtopicDenamespacer(MINIMAL_VAPIX_NAMESPACES)
      self.params = {}

   #----------------------------------------------------------------------------
   # Communication functions                                                {{{2
   #----------------------------------------------------------------------------

   def _dump_request(self, req, data = None):
      if self.debug:
         print('\nRequest:\n========\n')
         print(req)
         if data:
            print('\nData:\n--------\n')
            print(data)
         sys.stdout.flush()

   def _dump_plain_reply(self, plain_data):
      if self.debug:
         print('\nReply:\n========\n')
         print(plain_data)
         sys.stdout.flush()

   def _dump_txt_request_as_xml(self, req):
      if self.debug:
         print('\nRequest:\n========\n')
         x = ET.fromstring(req)
         xml_indent(x)
         ET.dump(x)
         sys.stdout.flush()

   def _dump_xml_reply(self, xml):
      if self.debug:
         print('\nReply:\n====\n')
         xml_indent(xml)
         ET.dump(xml)
         sys.stdout.flush()

   def _simple_vapix_call(self, url : str, data : str = None, extra_headers : str = {}, mode : str = None):
      """
      Perform a GET or POST with a VAPIX request
      """
      self._dump_request(url, data)
      if data or mode == 'POST':
         rawdata = self.w.post(url, data, extra_headers).read()
      else:
         rawdata = self.w.get(url).read()
      self._dump_plain_reply(rawdata)
      return rawdata

   def _json_vapix_call(self, url, data : Optional[Union[dict, str]] = None) -> dict:
      """
      Perform a JSON Vapix-call, dict or string in, dict out
      """
      if isinstance(data, str):
         # Sanity check (better message here than from camera)
         _ = json.loads(data)
      elif isinstance(data, dict):
         data = json.dumps(data)

      return json.loads(
         self._simple_vapix_call(
            url,
            data,
            extra_headers={'Content-Type': 'application/json', 'Accept-Encoding': 'application/json'}
         ).decode('utf-8')
      )

   def _simple_vapix_webservice_call(self, req):
      self._dump_txt_request_as_xml(req)
      try:
         r = self.w.post('/vapix/services', req)
         rawdata = r.read()
      except urllib.error.HTTPError as v:
         if v.code in (400, 500):
            rawdata = v.read()
         else:
            raise
      envelope = ET.fromstring(rawdata)
      self._dump_xml_reply(envelope)
      return envelope

   def _simple_vapix_xml_response_call(self, url):
      self._dump_request(url)
      rawdata = self.w.get(url).read()
      envelope = ET.fromstring(rawdata)
      self._dump_xml_reply(envelope)
      return envelope

   #----------------------------------------------------------------------------
   # System functions                                                       {{{2
   #----------------------------------------------------------------------------

   def GetSomeInfo(self):
      """
      Call: GetSomeInfo

      Retrieve opiniated set of properties from a device which are typically
      important for a device driver to know about
      """
      url = ','.join( [
            '/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName',
            'Properties',
            'Network.RTSP.AllowClientTransportSettings',
            'Input.NbrOfInputs',
            'Output.NbrOfOutputs',
            'IOPort.*.Configurable'] )
      self._dump_request(url)
      r = self.w.get(url)
      print(r.read().decode('utf-8'))

   def EnableSSH(self):
      """
      EnableSSH on a fw 5.60+ device

      Call: EnableSSH
      """
      return self._simple_vapix_call('/axis-cgi/param.cgi?action=update&Network.SSH.Enabled=yes')

   def FactoryDefault(self):
      """
      Perform a soft factory default, aka 'restore', maintaining the networking parameters

      Call: FactoryDefault
      """
      return self._simple_vapix_call('/axis-cgi/factorydefault.cgi').decode('utf-8')

   def HardfactoryDefault(self):
      """
      Perform a hard factory default, aka 'factory default'

      Call: HardfactoryDefault
      """
      return self._simple_vapix_call('/axis-cgi/hardfactorydefault.cgi').decode('utf-8')

   def Reboot(self):
      """
      Call: Reboot
      """
      return self.w.get( '/axis-cgi/restart.cgi' ).read()

   def Wait(self, seconds = 60):
      """
      Wait a certain time

      Call: Wait(seconds=X)
      """
      time.sleep(int(seconds))

   #----------------------------------------------------------------------------
   # Troubleshooting                                                        {{{2
   #----------------------------------------------------------------------------

   def PerformTrace(self, duration = 300, filename = None):
      """
      Call: PerformTrace([duration=seconds] (*300), filename=[filename])

      Let the camera perform a trace for a number of seconds (default: 30).
      The result can be inspected with Wireshark
      """
      r = self.w.get(f'/axis-cgi/debug/debug.tgz?cmd=pcapdump&duration={duration}')
      name = filename
      if not filename:
         name = os.path.basename(self.w.site_url) + '.pcap'
      with open(name, 'wb') as f:
         f.write(r.read())
      return name

   def GetServerReport( self, mode = 'zip_with_image' ):
      """"
      Get a serverreport from a camera. The file is saved
      in current directory.

      Call: GetServerReport(mode=[zip, *zip_with_image])

      Default is mode zip_with_image
      """
      url = f'/axis-cgi/admin/serverreport.cgi?mode={mode}'
      self._dump_request(url)
      r = self.w.get(url)
      filename = None
      headers = r.info()
      if 'Content-Disposition' in headers:
         tokens = headers['Content-Disposition'].split('=')
         if tokens[0].endswith( 'filename' ):
            filename = tokens[1]
      if filename is None:
         # TODO: use current ip address
         filename = f'ServerReport-{GLOBAL_COUNTER:>010}'
      write_data(filename, r.read())
      return filename

   def GetSystemLog(self):
      """
      Retrieve the (entire) systemlog

      Call: GetSystemLog
      """
      return self._simple_vapix_call('/axis-cgi/admin/systemlog.cgi').decode('utf-8')

   #----------------------------------------------------------------------------
   # ACAP                                                                   {{{2
   #----------------------------------------------------------------------------

   def _acapCmd(self, action, package):
      """
      Call: _acapCmd(action=action,package=package_name)

      Perform an ACAP control operation
      """
      return self._simple_vapix_call(
         f'/axis-cgi/applications/control.cgi?action={action}&package={package}')

   def ListAcaps(self):
      """
      Call: ListAcaps

      List the installed ACAPs
      """
      url = '/axis-cgi/applications/list.cgi'
      return self._simple_vapix_call(url)

   def StartAcap(self, package):
      """
      Call: StartAcap(package=package_name)

      Start the ACAP named 'package'
      """
      return self._acapCmd('start', package)

   def RestartAcap(self, package):
      """
      Call: RestartAcap(package=package_name)

      Restart the ACAP named 'package'
      """
      return self._acapCmd('restart', package)

   def StopAcap(self, package):
      """
      Call: StopAcap(package=package_name)

      Stop the ACAP named 'package'
      """
      return self._acapCmd('stop', package)

   def RemoveAcap(self, package ):
      """
      Call: RemoveAcap(package=package_name)

      Remove the ACAP named 'package'
      """
      return self._acapCmd('remove', package)

   def UploadAcap(self, filename):
      """
      Call: UploadAcap(filename=path/to/eap_file)

      Upload an ACAP
      """
      if os.path.isfile(filename):
         return self.w.post_file(
            url_str = '/axis-cgi/applications/upload.cgi',
            filename = filename,
            content_type = 'application/octet-stream')
      else:
         print(f'File not found: {filename}')
         return None

   #----------------------------------------------------------------------------
   # Event Information                                                      {{{2
   #----------------------------------------------------------------------------

   def GetEventInfo(self):
      """
      Call: GetEventInfo

      Get the events supported by the camera (generated by Axis OS or enabled
      applications on the device). The information can be used to contruct
      event subscriptions on the event data stream
      """

      def nice_name( node ):
         """
         Return a human readable node name which is either the denamespaced
         node tag or its NiceName attribute
         """
         name = node.tag
         for attrib in list(node.keys()):
            if attrib.endswith('NiceName'):
               name = node.get( attrib )
               break
         return re.sub('{.*}', '', name)

      def show_event(subcategory, event, tf_base):
         event_name = nice_name(event)
         event_title = f'{subcategory}{" - " if len(subcategory) else ""}{event_name}'
         print(f' {event_title:<40}\teventtopic={tf_base}/{self.denamespacer.tag(event.tag)}')

      request_body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema"> <GetEventInstances xmlns="http://www.axis.com/vapix/ws/event1"/></s:Body></s:Envelope>'
      envelope = self._simple_vapix_webservice_call(request_body)

      topic_set = envelope.find('SOAP-ENV:Body/aev:GetEventInstancesResponse/wstop:TopicSet', MINIMAL_VAPIX_NAMESPACES)
      for topic in list(topic_set):
         topic_filterbase = self.denamespacer.tag(topic.tag)
         print(f'\n{nice_name(topic)}')

         for event_or_group in list(topic):
            # If a direct child in 'topic' itself has a 'MessageInstance', it
            # is an event declaration, otherwise it is a group of events and
            # we have to look for the events one level deeper

            # TODO: Need to filter out the isDeprecated's
            message_instance = event_or_group.find('aev:MessageInstance', MINIMAL_VAPIX_NAMESPACES)
            if message_instance is None:
               # Group of events, cycle one level deeper
               group_name = nice_name(event_or_group)
               # print(f'group_name: {group_name}, tag: {event_or_group.tag}')
               topic_filterextension = self.denamespacer.tag(event_or_group.tag)
               # print('nested: {} {} {} {}'.format(group_name, namespace, node_name, topic_filterextension))
               for event in list(event_or_group):
                  # print('event: {}'.format(event.tag))
                  show_event(group_name, event, topic_filterbase + '/' + topic_filterextension)
            else:
               # Event
               show_event('', event_or_group, topic_filterbase)

   def ListFeatureFlags(self):
      """
      List the available feature flags
      """
      return self._json_vapix_call(
         '/axis-cgi/featureflag.cgi',
         LIST_FEATUREFLAGS)

#-------------------------------------------------------------------------------
#
#   Main                                                                    {{{1
#
#-------------------------------------------------------------------------------

class Executor:
   """
   A class to assemble the list of functions to call, and runnning the requested sequence
   """
   def __init__(self, args):
      self.args = args
      self.clients = {}
      self.iteration_counter = 0
      for cam in args.camera:
         w = WebAccess(f'http://{cam}')
         w.add_credentials(args.user, args.password)
         self.clients[cam] = VapixClient(w, args.raw)

   def run(self):
      """
      Runs the functions
      """
      global GLOBAL_COUNTER
      if self.args.function is not None and self.args.camera is not None:
         if self.args.iterations == -1:
            self._run_one(True)
         else:
            self.iteration_counter = 0
            while self.iteration_counter < self.args.iterations or (self.args.iterations == 0):
               self._run_one(self.iteration_counter == 0)
               self.iteration_counter += 1
               GLOBAL_COUNTER = self.iteration_counter
               if (self.iteration_counter < self.args.iterations) or (self.args.iterations == 0):
                  print(
                    f'{datetime.datetime.now()} End of iteration {self.iteration_counter}{"" if self.args.iterations == 0 else "/"}{"" if not self.args.iterations else self.args.iterations}. Sleeping for {self.args.sleep2} seconds...')
                  sys.stdout.flush()
                  time.sleep(float(self.args.sleep2))
            print('Done')
      else:
         print('No device(s) and/or function(s) specified')

   def _run_one(self, verbose: bool = False):
      """
      Run the list of functions one time
      """
      for c in self.args.camera:
         if verbose:
            print(f'Camera = {c}')
         for f in self.args.function:
            name, kwargs = parse_call(f)
            methodcall = None
            if name in TOOL_LIST:
               methodcall = getattr(self.clients[c], name)
            else:
               print(f'Unsupported: {f}')
            if methodcall:
               if verbose:
                  print(f'Calling: {name}({kwargs})')
               r = methodcall(**kwargs)
               if isinstance(r, str):
                  print(r)
               elif isinstance(r, bytes):
                  print(r.decode('utf-8'))
               else:
                  pprint.pprint(r)
            else:
               print('No such function:', name)
            if self.args.sleep1:
               print(f'Sleep for {self.args.sleep1} seconds')
               time.sleep(float(self.args.sleep1))


if __name__ == '__main__':

   config = configparser.RawConfigParser()
   config['default'] = {}
   config['default']['user'] = 'root'
   config['default']['password'] = 'pass'

   EAP_FILE = '.eap-install.cfg'
   if os.path.isfile(EAP_FILE):
      settings = '[default]\n'
      with open(EAP_FILE, 'r', encoding='utf-8') as _f:
         settings += _f.read()
      config.read_string(settings)

   def get_functions(the_class):
      """
      Get the list of supported functions
      """
      return [m for m in dir(the_class) if isinstance(getattr(the_class, m), collections.abc.Callable) and not m.startswith('_')]

   TOOL_LIST = get_functions(VapixClient)

   parser = argparse.ArgumentParser(
       description = 'Collection of commands to interact with Axis cameras.\nCommands can be run in sequence with wait times in between',
       formatter_class = argparse.RawDescriptionHelpFormatter,
       epilog = 'Functions:\n{}\n\n'.format('\n'.join(TOOL_LIST))
   )

   parser.add_argument(
        '-c', '--camera', type = str, action='append',
        help='Hostname/IP address of the device(s) to interact with. You can specify multiple cameras')
   parser.add_argument(
        '-u', '--user', type = str, default = config['default']['user'],
        help = f'username to login with ({config["default"]["user"]})')
   parser.add_argument(
        '-p', '--password', type = str, default = config['default']['password'],
        help = f'password to login with ({config["default"]["password"]})')
   parser.add_argument(
        '-x', '--proxy', type = str, default = None,
        help = 'proxy to use, e.g. "http://user:pass@proxyaddr:proxyport" (none)')
   parser.add_argument(
        '-f', '--function', action = 'append',
        help = 'Function to call. You can specify multiple -f arguments')
   parser.add_argument(
        '-d', '--document', action ='store_true',
        help = 'Get detailed documentation on calling a function')
   parser.add_argument(
        '-r', '--raw', action = 'store_true',
        help = 'Output raw request+response instead of processed response only (functions that don\'t process always dump raw response)')
   parser.add_argument(
        '-i', '--iterations', type = int, default = -1,
        help = 'How many times to repeat the requests (no repetition). 0 repeats endless')
   parser.add_argument(
        '-s', '--sleep1', type = int, default = 0,
        help = 'Sleeptime between functions (0)')
   parser.add_argument(
        '-S', '--sleep2', type = int, default = 7200,
        help = 'Sleeptime between iterations (7200)')

   args = parser.parse_args()
   if args.camera is None:
      if 'axis_device_ip' in config['default']:
         args.camera = [ config['default']['axis_device_ip'] ]

   if args.function is None or (args.camera is None and not args.document):
      parser.print_usage()
      sys.exit(2)

   #
   # If requested, the documentation and exit
   #

   if args.document:
      for func in args.function:
         if func in TOOL_LIST:
            print(getattr( VapixClient, func).__doc__)
         else:
            print(f'Unsupported: {func}')
      sys.exit(0)

   Executor(args).run()

#  vim: set nowrap sw=3 sts=3 et fdm=marker:
