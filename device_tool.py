"""
device_tool
-----------
A script to perform some operations on Axis devices.
Requires Python 3.8+

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

      python3 device_tool.py -f "UploadAcap(filename=youracap_0_8_5_armv7hf.eap)" -f ListAcaps -f "StartAcap(package=youracap)" \
        -f "Wait(seconds=120)" -f "RemoveAcap(package=youracap)" -f ListAcaps

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
import ssl
from typing import Optional, Union, Dict, List, Type
import xml.etree.ElementTree as ET
import pprint
import configparser

import collections.abc
from abc import ABC, abstractmethod

import http.cookiejar
import http.client

import urllib.parse
import urllib.error
import urllib.request
import urllib.response

GLOBAL_COUNTER = 0

# -------------------------------------------------------------------------------
#
#   Utilities                                                               {{{1
#
# -------------------------------------------------------------------------------

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
      self.pattern = re.compile(r'{(.*)}(.*)')
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
         if (m := self.pattern.match(elementtree_tag)):
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


def parse_call(func_call):
   """
   This one splits a command-line string into a function-name and keyword
   arguments list that can be passed to the function implementing
   'function-name'
   """
   part1 = func_call.strip().split('(')
   kwargs = {}
   if len(part1) > 1 and len(part1[1]) > 1:
      args = part1[1][:-1].split(',')
      for a in args:
         x = a.split('=', 1)
         kwargs[x[0]] = x[1]
   return part1[0], kwargs

# In-place ElementTree prettyprint formatter
# Credits: http://effbot.oRg/zone/element-lib.htm#prettyprint


def xml_indent(elem, level=0):
   i = "\n" + level * "  "
   if len(elem):
      if not elem.text or not elem.text.strip():
         elem.text = i + "  "
      if not elem.tail or not elem.tail.strip():
         elem.tail = i
      for sub_el in elem:
         xml_indent(sub_el, level + 1)
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

# -------------------------------------------------------------------------------
#
#   Web access                                                              {{{1
#
# -------------------------------------------------------------------------------


DEBUG_HTTP = 0

# Example proxy: 'http://username:password@proxy.yourdomain:3128'


def StandardSSLContext():
   """
   Return a SSL context that tells to ignore certificate validity. Maybe not a
   good idea in general but it does gets us through invalid configurations and
   perform hard factory defaults
   """
   ctx = ssl.create_default_context()
   ctx.check_hostname = False
   ctx.verify_mode = ssl.CERT_NONE
   return ctx

class WebAccess:
   """
   A urllib based http-client. There are no real advantages to the urllib
   approach other than to keep this script free of non-standard
   dependencies, like requests
   """

   def __init__(self, host: str, temp_dir='.', proxy=None, context=None):
      self.host = host
      self.site_url = f'http://{host}'
      self.pwd_mngr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
      self.cj = http.cookiejar.LWPCookieJar()
      self.cookie_file = temp_dir + os.sep + 'cookie.lwp'
      self.h = []
      self.h.append(urllib.request.HTTPHandler(debuglevel=DEBUG_HTTP))
      self.h.append(urllib.request.HTTPSHandler(
          debuglevel=DEBUG_HTTP, context=context))
      self.h.append(urllib.request.HTTPDigestAuthHandler(self.pwd_mngr))
      self.h.append(urllib.request.HTTPBasicAuthHandler(self.pwd_mngr))
      if proxy:
         self.h.append(urllib.request.ProxyHandler({'http': proxy}))
      self.opener = urllib.request.build_opener(*self.h)
      self.context = context

   def __del__(self):
      pass

   def add_credentials(self, usr, passw, url=None):
      if url is None:
         url = self.site_url
      self.pwd_mngr.add_password(None, url, usr, passw)

   def get(self,
         url_str: str,
         extra_headers: Optional[Dict[str, str]] = None
   ) -> urllib.response.addinfourl:
      """
      Perform a HTTP GET
      """
      url = self.site_url + url_str
      if extra_headers is None:
         extra_headers = {}
      return self.opener.open(urllib.request.Request(url=url, headers=extra_headers))

   def post(self,
         url_str: str,
         params: Optional[Union[bytes,str]] = None,
         extra_headers: Optional[Dict[str, str]] = None
   ) -> urllib.response.addinfourl:
      """
      Perform a HTTP POST
      """
      url = self.site_url + url_str
      if extra_headers is None:
         extra_headers = {}
      if isinstance(params, str):
         req = urllib.request.Request(url, params.encode('utf-8'), headers=extra_headers)
      else:
         req = urllib.request.Request(url, params, headers=extra_headers)
      return self.opener.open(req)

   def post_file(self,
         url_str: str,
         filename: str,
         content_type: str = 'text/plain',
         uploadname: Optional[str] = None,
         extra_headers: Optional[Dict[str, str]] = None
   ) -> urllib.response.addinfourl:
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
         upload_text = b'--' + my_boundary + b'\r\n' + upload_prefix + f.read() + \
           upload_postfix + b'--' + my_boundary + b'--\r\n'
      h = extra_headers if isinstance(extra_headers, dict) else {}
      h.update({
         'Content-Type': 'multipart/form-data; boundary=' + my_boundary.decode('utf-8'),
         'Content-Length': f'{len(upload_text)}'
      })
      return self.opener.open(urllib.request.Request(url, upload_text, headers=h))

# -------------------------------------------------------------------------------
#
#   Events and Actions support functions                                    {{{1
#
# -------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
# Schedules                                                                 {{{2
#-------------------------------------------------------------------------------

AddScheduleXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
  <AddScheduledEvent xmlns="http://www.axis.com/vapix/ws/event1">
   <NewScheduledEvent>
    <Name>{0}</Name>
    <Schedule>
     <ICalendar Dialect="http://www.axis.com/vapix/ws/ical1">{1}</ICalendar>
    </Schedule>
   </NewScheduledEvent>
  </AddScheduledEvent>
 </Body>
</Envelope>
"""

AddScheduleWithIDXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
  <AddScheduledEvent xmlns="http://www.axis.com/vapix/ws/event1">
   <NewScheduledEvent>
    <Name>{0}</Name>
    <EventID>{1}</EventID>
    <Schedule>
     <ICalendar Dialect="http://www.axis.com/vapix/ws/ical1">{2}</ICalendar>
    </Schedule>
   </NewScheduledEvent>
  </AddScheduledEvent>
 </Body>
</Envelope>
"""

RemoveScheduleXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
  <RemoveScheduledEvent xmlns="http://www.axis.com/vapix/ws/event1">
   <EventID>{0}</EventID>
  </RemoveScheduledEvent>
 </Body>
</Envelope>
"""

ListSchedulesXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body>
   <GetScheduledEvents xmlns="http://www.axis.com/vapix/ws/event1"/>
 </Body>
</Envelope>
"""

#-------------------------------------------------------------------------------
# Recipients                                                                {{{2
#-------------------------------------------------------------------------------

GenericRecipientConfiguration = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:act="http://www.axis.com/vapix/ws/action1" xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
	<act:AddRecipientConfiguration xmlns="http://www.axis.com/vapix/ws/action1">
	  <NewRecipientConfiguration>
		<TemplateToken>{}</TemplateToken>
		<Name>{}</Name>
		<Parameters>
          {}
		</Parameters>
	  </NewRecipientConfiguration>
	</act:AddRecipientConfiguration>
  </soap:Body>
</soap:Envelope>
"""

# This info can be requested from the camera as well, but that doesn't really
# scale when configuring a lot of devices

RecipientDefinitions = {
  'com.axis.recipient.tcp':  {'host': '', 'port': '', 'qos': '0'},
  'com.axis.recipient.http': {'upload_url': '', 'login': '', 'password': '', 'qos': '0', 'proxy_host': '', 'proxy_port': '', 'proxy_login': '', 'proxy_password': ''},
  'com.axis.recipient.https': {'upload_url': '', 'login': '', 'password': '', 'qos': '0', 'proxy_host': '', 'proxy_port': '', 'proxy_login': '', 'proxy_password': '', 'validate_server_cert': '1'}
}

def MakeRecipientConfiguration(token, name, **kwargs):
   if token in RecipientDefinitions:
      params = []
      for key in RecipientDefinitions[token].keys():
         value = kwargs.get(key, RecipientDefinitions[token][key])
         params.append('<Parameter Name="{}" Value="{}"></Parameter>'.format(key, value))
      return GenericRecipientConfiguration.format(token, name, '\n'.join(params))
   return None

#-------------------------------------------------------------------------------
# ActionConfiguration and -Rules                                            {{{2
#-------------------------------------------------------------------------------

GenericActionEnvelope = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:act="http://www.axis.com/vapix/ws/action1" xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Body>
		<act:{0} xmlns="http://www.axis.com/vapix/ws/action1">
		</act:{0}>
	</soap:Body>
</soap:Envelope>
"""
GenericActionRule = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" >
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body xmlns:act="http://www.axis.com/vapix/ws/action1" xmlns:aev="http://www.axis.com/vapix/ws/event1" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:tnsaxis="http://www.axis.com/2009/event/topics">
      <act:AddActionRule>
        <act:NewActionRule>
          <act:Name>{0}</act:Name>
             {1}
          <act:Enabled>true</act:Enabled>
          <act:Conditions>
             {2}
          </act:Conditions>
          <act:PrimaryAction>{3}</act:PrimaryAction>
        </act:NewActionRule>
      </act:AddActionRule>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

GenericCondition = """<act:Condition>
   <wsnt:TopicExpression Dialect="http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete">{0}</wsnt:TopicExpression>
   <wsnt:MessageContent Dialect="http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter">{1}</wsnt:MessageContent>
</act:Condition>
"""

GenericStartEvent = """<act:StartEvent>
  <wsnt:TopicExpression Dialect="http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete" xmlns="http://docs.oasis-open.org/wsn/b-2">{0}</wsnt:TopicExpression>
  <wsnt:MessageContent Dialect="http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter" xmlns="http://docs.oasis-open.org/wsn/b-2">{1}</wsnt:MessageContent>
</act:StartEvent>
"""


ActionDefinitions = {
  'com.axis.action.fixed.notification.http': {
     'recipient_token': 'com.axis.recipient.http',
     'params': {'parameters': '', 'message': ''}
  },
  'com.axis.action.fixed.notification.https': {
     'recipient_token': 'com.axis.recipient.https',
     'params': {'parameters': '', 'message': ''}
  },
  'com.axis.action.fixed.play.audioclip': {
     'recipient_token': None,
     'params': {
        'location': '',
#        'audiooutput': '',
#        'audiodeviceid': '0',
#        'audiooutputid': '0',
#        'repeat': '0',
#        'volume': '100'
     }
  }
}

GenericActionConfiguration = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
   <SOAP-ENV:Header/>
   <SOAP-ENV:Body xmlns:act="http://www.axis.com/vapix/ws/action1" xmlns:aev="http://www.axis.com/vapix/ws/event1" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:tnsaxis="http://www.axis.com/2009/event/topics">
     <act:AddActionConfiguration>
      <act:NewActionConfiguration>
        <act:Name>{}</act:Name>
        <act:TemplateToken>{}</act:TemplateToken>
        <act:Parameters>
         {}
        </act:Parameters>
      </act:NewActionConfiguration>
     </act:AddActionConfiguration>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

GenericRemoveEnvelope = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:act="http://www.axis.com/vapix/ws/action1" xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Body>
		<act:{0} xmlns="http://www.axis.com/vapix/ws/action1">
          <act:{1}>{2}</act:{1}>
		</act:{0}>
	</soap:Body>
</soap:Envelope>
"""

GET_RECIPIENT_TEMPLATES = GenericActionEnvelope.format('GetRecipientTemplates')
GET_RECIPIENT_CONFIGURATIONS = GenericActionEnvelope.format('GetRecipientConfigurations')
GET_ACTION_RULES = GenericActionEnvelope.format('GetActionRules')
GET_ACTION_CONFIGURATIONS = GenericActionEnvelope.format('GetActionConfigurations')

REMOVE_ACTION_CONFIGURATION = GenericRemoveEnvelope.format('RemoveActionConfiguration', 'ConfigurationID', '{}')
REMOVE_ACTION_RULE = GenericRemoveEnvelope.format('RemoveActionRule', 'RuleID', '{}')
REMOVE_RECIPIENT_CONFIGURATION = GenericRemoveEnvelope.format('RemoveRecipientConfiguration', 'ConfigurationID', '{}')

class TopicFilter(ABC):
   def __init__(self, topic, content_filter):
      self.topic = topic
      self.content_filter = content_filter

   @abstractmethod
   def serialize(self):
      pass

class Condition(TopicFilter):

   def serialize(self):
      return GenericCondition.format(self.topic, self.content_filter)

class StartEvent(TopicFilter):

   def serialize(self):
      return GenericStartEvent.format(self.topic, self.content_filter)

class ConditionList:
   def __init__(self):
      self.conditions = []

   def add(self, topic, content_filter):
      self.conditions.append(Condition(topic, content_filter))

   def serialize(self):
      return '\n'.join([c.serialize() for c in self.conditions])

def MakeActionConfiguration(token, name, **kwargs):
   """
   Generate an action configuration 'in place', use recipient parameters as
   present in 'kwargs'

   The action configuration parameter content is a merge of the recipient
   template parameters and the action template
   """
   if token in ActionDefinitions:
      recipient_token = ActionDefinitions[token]['recipient_token']
      params = []
      for key, default_val in ActionDefinitions[token]['params'].items():
         params.append('<act:Parameter Name="{}" Value="{}"/>'.format(key, kwargs.get(key,  default_val)))
      if recipient_token is not None:
         if recipient_token not in RecipientDefinitions:
            return None
         for key, default_val in RecipientDefinitions[recipient_token].items():
            params.append('<act:Parameter Name="{}" Value="{}"/>'.format(key, kwargs.get(key, default_val)))
      return GenericActionConfiguration.format(name, token, '\n'.join(params))
   print(f'Error: no action-template for {token}')
   return None

# -------------------------------------------------------------------------------
#
#   VAPIX Client                                                            {{{1
#
# -------------------------------------------------------------------------------

# See: https://stackoverflow.com/questions/55921412


MINIMAL_VAPIX_NAMESPACES = {
   'SOAP-ENV': 'http://www.w3.org/2003/05/soap-envelope',
   'aev': 'http://www.axis.com/vapix/ws/event1',
   'wstop': 'http://docs.oasis-open.org/wsn/t-1',
   'tns1': 'http://www.onvif.org/ver10/topics',
   'tnsaxis': 'http://www.axis.com/2009/event/topics',
   'act': 'http://www.axis.com/vapix/ws/action1',
   'entry': 'http://www.axis.com/vapix/ws/entry',
   'tds': 'http://www.onvif.org/ver10/device/wsdl',
   'tt': 'http://www.onvif.org/ver10/schema'
}

LIST_FEATUREFLAGS = """
{
  "apiVersion": "1.0",
  "context": "my context",
  "method": "listAll"
}
"""

SET_CUSTOM_HEADER = """{{
  "apiVersion": "1.0",
  "context": "OptionalContext",
  "method": "set",
  "params": {{
    "{}": "{}"
  }}
}}"""

JSON_REQUEST = """{{
    "apiVersion": "{}",
    "context": "123",
    "method": "{}",
    "params": {}
}}
"""

GET_SUPPORTED_VERSIONS = """
{
    "context": "123",
    "method": "getSupportedVersions"
}
"""

MQTT_CLIENT_STATUS = JSON_REQUEST.format('1.0', 'getClientStatus', '{}')
MQTT_ACTIVATE_CLIENT = JSON_REQUEST.format('1.0', 'activateClient', '{}')
MQTT_DEACTIVATE_CLIENT = JSON_REQUEST.format('1.0', 'deactivateClient', '{}')

MD_LIST_PRODUCERS = JSON_REQUEST.format('1.0', 'listProducers', '{}')
MD_GET_SUPPORTED_METADATA = JSON_REQUEST.format('1.0', 'getSupportedMetadata', '{}')


GetDot1XConfigXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
    <GetDot1XConfiguration xmlns="http://www.onvif.org/ver10/device/wsdl"><Dot1XConfigurationToken>{token}</Dot1XConfigurationToken></GetDot1XConfiguration>
 </Body>
</Envelope>
"""

SetDot1XConfigXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
   <SetDot1XConfiguration xmlns="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
     <Dot1XConfiguration>
       <tt:Dot1XConfigurationToken>{token}</tt:Dot1XConfigurationToken>
       <tt:Identity>{mac}</tt:Identity>
       <tt:EAPMethod>{method}</tt:EAPMethod>
       <tt:EAPMethodConfiguration>
           <tt:TLSConfiguration>
             <tt:CertificateID>{certname}</tt:CertificateID>
           </tt:TLSConfiguration>
       </tt:EAPMethodConfiguration>
       {cacert_spec}
     </Dot1XConfiguration>
   </SetDot1XConfiguration>
 </Body>
</Envelope>
"""

GetCACertificatesXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
<GetCACertificates xmlns="http://www.onvif.org/ver10/device/wsdl"></GetCACertificates>
 </Body>
</Envelope>
"""

DeleteCertificateXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
<DeleteCertificates xmlns="http://www.onvif.org/ver10/device/wsdl"><CertificateID>{}</CertificateID></DeleteCertificates>
 </Body>
</Envelope>
"""

LoadCACertificatesXml = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
 <Header/>
 <Body >
   <LoadCACertificates xmlns="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
     <CACertificate>
       <tt:CertificateID>202512_testroom_RADIUS_2_CA</tt:CertificateID>
       <tt:Certificate>
          <tt:Data>{body}</tt:Data>
       </tt:Certificate>
     </CACertificate>
   </LoadCACertificates>
 </Body>
</Envelope>
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

   def __init__(self, w, dump_raw_bytes=False):
      self.w = w
      self.debug = dump_raw_bytes
      # SOAP-related
      for key, val in MINIMAL_VAPIX_NAMESPACES.items():
         ET.register_namespace(key, val)
      # Used for converting vapix namespaces to topicfilter namespaces
      self.denamespacer = EventtopicDenamespacer(MINIMAL_VAPIX_NAMESPACES)
      self.params = {}

   @classmethod
   def functions(cls):
      """
      Return the list of supported functions
      """
      return [m for m in dir(cls) if isinstance(getattr(cls, m), collections.abc.Callable) and not m.startswith('_')]

   # ----------------------------------------------------------------------------
   # Communication functions                                                {{{2
   # ----------------------------------------------------------------------------

   def _dump_request(self, req: str, data=None):
      if self.debug:
         print(f'\nRequest:\n========\n{req}\n')
         if data:
            print('\nData:\n--------\n')
            print(data)
         sys.stdout.flush()

   def _dump_plain_reply(self, plain_data: bytes):
      if self.debug:
         print(f'\nReply:\n========\n{plain_data.decode("utf-8")}\n')
         sys.stdout.flush()

   def _dump_xml(self, title: str, xml : ET.Element):
      if self.debug:
         print(f'\n{title}:\n========\n')
         xml_indent(xml)
         ET.dump(xml)
         sys.stdout.flush()

   def _dump_xml_request(self, xml : ET.Element):
      self._dump_xml('Request', xml)

   def _dump_xml_reply(self, xml : ET.Element):
      self._dump_xml('Reply', xml)

   def _dump_txt_request_as_xml(self, req):
      if self.debug:
         print('\nRequest:\n========\n')
         x = ET.fromstring(req)
         xml_indent(x)
         ET.dump(x)
         sys.stdout.flush()

   def _simple_vapix_call(self,
         url: str,
         data: Optional[str] = None,
         extra_headers: Optional[Dict[str, str]] = None,
         method: Optional[str] = None
   ) -> bytes:
      """
      Perform a GET or POST with a VAPIX request

      It does POST when data is provided or the method is 'POST'.
      """
      self._dump_request(url, data)
      if extra_headers is None:
         extra_headers = {}
      if data or method == 'POST':
         rawdata = self.w.post(url, data, extra_headers).read()
      else:
         rawdata = self.w.get(url).read()
      self._dump_plain_reply(rawdata)
      return rawdata

   def _json_vapix_call(
       self, url, data: Union[dict, str]
   ) -> dict:
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
            extra_headers = {
               'Content-Type': 'application/json',
               'Accept-Encoding': 'application/json'
            }
         ).decode('utf-8')
      )

   def _simple_vapix_webservice_call(self, req: str) -> ET.Element:
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

   def _simple_vapix_xml_response_call(self, url) -> ET.Element:
      self._dump_request(url)
      rawdata = self.w.get(url).read()
      envelope = ET.fromstring(rawdata)
      self._dump_xml_reply(envelope)
      return envelope

   # ----------------------------------------------------------------------------
   # System functions                                                       {{{2
   # ----------------------------------------------------------------------------

   def GetSomeInfo(self) -> str:
      """
      Call: GetSomeInfo

      Retrieve opiniated set of properties from a device which are typically
      important for a device driver to know about
      """
      url = ','.join([
            '/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName',
            'Properties',
            'Network.RTSP.AllowClientTransportSettings',
            'Input.NbrOfInputs',
            'Output.NbrOfOutputs',
            'IOPort.*.Configurable'])
      return self._simple_vapix_call(url).decode('utf-8')

   def EnableSSH(self) -> str:
      """
      EnableSSH on a fw 5.60+ device

      Call: EnableSSH
      """
      return self._simple_vapix_call(
          '/axis-cgi/param.cgi?action=update&Network.SSH.Enabled=yes').decode('utf-8')

   def FactoryDefault(self) -> str:
      """
      Perform a soft factory default, aka 'restore', maintaining the networking parameters

      Call: FactoryDefault
      """
      return self._simple_vapix_call(
          '/axis-cgi/factorydefault.cgi').decode('utf-8')

   def HardfactoryDefault(self) -> str:
      """
      Perform a hard factory default, aka 'factory default'

      Call: HardfactoryDefault
      """
      return self._simple_vapix_call(
          '/axis-cgi/hardfactorydefault.cgi').decode('utf-8')

   def Reboot(self) -> str:
      """
      Call: Reboot
      """
      return self._simple_vapix_call('/axis-cgi/restart.cgi').decode('utf-8')

   def CustomHeader(self, header: str = 'Access-Control-Allow-Origin', value: str = '*') -> str:
      """
      Call: CustomHeader(header=<str>,value=<str>)

      Device needs reboot for the setting to have effect
      """
      return self._simple_vapix_call(
         '/axis-cgi/customhttpheader.cgi',
         SET_CUSTOM_HEADER.format(header, value)
      ).decode('utf-8')

   def Wait(self, seconds=60) -> str:
      """
      Wait a certain time

      Call: Wait(seconds=X)
      """
      time.sleep(int(seconds))
      return ''

   # ----------------------------------------------------------------------------
   # Simple properties                                                      {{{2
   # ----------------------------------------------------------------------------

   def GetSerialNumber(self):
      raw_serial = self._simple_vapix_call('/axis-cgi/param.cgi?action=list&group=Properties.System.SerialNumber').decode('utf-8')
      return raw_serial.split('=')[1].strip()

   # ----------------------------------------------------------------------------
   # Troubleshooting                                                        {{{2
   # ----------------------------------------------------------------------------

   def PerformTrace(self, duration: int = 300,
                    filename: Optional[str] = None) -> str:
      """
      Call: PerformTrace([duration=seconds] (*300), filename=[filename])

      Let the camera perform a trace for a number of seconds (default: 30).
      The result can be inspected with Wireshark
      """
      r = self.w.get(
          f'/axis-cgi/debug/debug.tgz?cmd=pcapdump&duration={duration}')
      if not (name := filename):
         name = os.path.basename(self.w.site_url) + '.pcap'
      with open(name, 'wb') as f:
         f.write(r.read())
      return name

   def GetServerReport(self, mode='zip_with_image') -> str:
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
         if tokens[0].endswith('filename'):
            filename = tokens[1]
      if filename is None:
         filename = f'ServerReport-{self.w.host}-{GLOBAL_COUNTER:>010}'
      write_data(filename, r.read())
      return filename

   def GetSystemLog(self) -> str:
      """
      Retrieve the (entire) systemlog

      Call: GetSystemLog
      """
      return self._simple_vapix_call(
          '/axis-cgi/admin/systemlog.cgi').decode('utf-8')

   # ----------------------------------------------------------------------------
   # ACAP                                                                   {{{2
   # ----------------------------------------------------------------------------

   def _acapCmd(self, action, package) -> str:
      """
      Call: _acapCmd(action=action,package=package_name)

      Perform an ACAP control operation
      """
      return self._simple_vapix_call(
         f'/axis-cgi/applications/control.cgi?action={action}&package={package}').decode('utf-8')

   def ListAcaps(self) -> str:
      """
      Call: ListAcaps

      List the installed ACAPs
      """
      url = '/axis-cgi/applications/list.cgi'
      return self._simple_vapix_call(url).decode('utf-8')

   def StartAcap(self, package) -> str:
      """
      Call: StartAcap(package=package_name)

      Start the ACAP named 'package'
      """
      return self._acapCmd('start', package)

   def RestartAcap(self, package) -> str:
      """
      Call: RestartAcap(package=package_name)

      Restart the ACAP named 'package'
      """
      return self._acapCmd('restart', package)

   def StopAcap(self, package) -> str:
      """
      Call: StopAcap(package=package_name)

      Stop the ACAP named 'package'
      """
      return self._acapCmd('stop', package)

   def RemoveAcap(self, package) -> str:
      """
      Call: RemoveAcap(package=package_name)

      Remove the ACAP named 'package'
      """
      return self._acapCmd('remove', package)

   def UploadAcap(self, filename) -> str:
      """
      Call: UploadAcap(filename=path/to/eap_file)

      Upload an ACAP
      """
      if os.path.isfile(filename):
         # Don't use _simple_vapix_call() to avoid -r printing the ACAP
         return self.w.post_file(
            url_str='/axis-cgi/applications/upload.cgi',
            filename=filename,
            content_type='application/octet-stream').read()
      else:
         return f'File not found: {filename}'

   # ----------------------------------------------------------------------------
   # I/O                                                                     {{{3
   # ----------------------------------------------------------------------------

   def VirtualIOOn(self, port = 1):
      """
      Call: VirtualIOOn(output=virtual port number)

      Set a virtualinput
      """
      return self._simple_vapix_call(f'/axis-cgi/virtualinput/activate.cgi?schemaversion=1&port={port}')

   def VirtualIOOff(self, port = 1):
      """
      Call: VirtualIOOff(output=virtual port number)

      Reset a virtualinput
      """
      return self._simple_vapix_call(f'/axis-cgi/virtualinput/deactivate.cgi?schemaversion=1&port={port}')

   # ----------------------------------------------------------------------------
   # Event Information                                                      {{{2
   # ----------------------------------------------------------------------------

   def GetEventInfo(self) -> str:
      """
      Call: GetEventInfo

      Get the supported events (generated by Axis OS or enabled applications
      on the device). The information can be used to contruct event
      subscriptions on the event data stream
      """
      result = []

      def nice_name(node) -> str:
         """
         Return a human readable node name which is either the denamespaced
         node tag or its NiceName attribute
         """
         name = node.tag
         for attrib in list(node.keys()):
            if attrib.endswith('NiceName'):
               name = node.get(attrib)
               break
         return re.sub('{.*}', '', name)

      def show_event(subcategory, event, tf_base):
         event_name = nice_name(event)
         event_title = f'{subcategory}{ " - " if len(subcategory) else ""}{event_name}'
         result.append(f' {event_title:<40}\teventtopic={tf_base}/{self.denamespacer.tag(event.tag)}')

      request_body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema"> <GetEventInstances xmlns="http://www.axis.com/vapix/ws/event1"/></s:Body></s:Envelope>'
      envelope = self._simple_vapix_webservice_call(request_body)

      if (topic_set := envelope.find(
          'SOAP-ENV:Body/aev:GetEventInstancesResponse/wstop:TopicSet', MINIMAL_VAPIX_NAMESPACES)) is not None:
         for topic in list(topic_set):
            topic_filterbase = self.denamespacer.tag(topic.tag)
            result.append(f'\n{nice_name(topic)}')

            for event_or_group in list(topic):
               # If a direct child in 'topic' itself has a 'MessageInstance', it
               # is an event declaration, otherwise it is a group of events and
               # we have to look for the events one level deeper

               if event_or_group.find('aev:MessageInstance', MINIMAL_VAPIX_NAMESPACES) is None:
                  group_name = nice_name(event_or_group)
                  topic_filterextension = self.denamespacer.tag(event_or_group.tag)
                  for event in list(event_or_group):
                     show_event(group_name, event, topic_filterbase + '/' + topic_filterextension)
               else:
                  # Event
                  show_event('', event_or_group, topic_filterbase)

      return '\n'.join(result)

   def ListFeatureFlags(self) -> str:
      """
      List the available feature flags
      """
      return json.dumps(self._json_vapix_call(
         '/axis-cgi/featureflag.cgi',
         LIST_FEATUREFLAGS
      ))

   # ----------------------------------------------------------------------------
   # Event & Action API                                                      {{{2
   # ----------------------------------------------------------------------------

   # ----------------------------------------------------------------------------
   # Schedules                                                               {{{3
   # ----------------------------------------------------------------------------

   def ListSchedules(self):
      """
      List the configured schedules (Recurrences)
      """
      return self._simple_vapix_webservice_call(ListSchedulesXml)

   def AddOrReplaceSchedule(self, name = 'TEST', event_id = None, ical_spec = 'DTSTART:19700101T080000\nDTEND:19700101T150000\nRRULE:FREQ=WEEKLY;BYDAY=TU,WE,TH'):
      """
      Add a schedule by first checking for existence of a schedule with the
      same name, if it exists delete it. Then add the schedule
      """
      return self.AddOrReplaceSchedules([{'name': name, 'event_id': event_id, 'ical_spec': ical_spec}])

   def AddOrReplaceSchedules(self, schedule_specifications : list):
      """
      Addition of multiple schedules. It starts with a single listing of existing
      schedules up-front to determine which ones to delete by name, and get to
      know their EventID so it can be reused in case adding a schedule is in
      fact recreating it.
      """
      def name_to_id(envelope, name):
         for schedule in list(envelope.find('SOAP-ENV:Body/aev:GetScheduledEventsResponse/aev:ScheduledEvents', MINIMAL_VAPIX_NAMESPACES)):
            if (ev_name := schedule.find('aev:Name', MINIMAL_VAPIX_NAMESPACES)) is not None:
               if name == ev_name.text:
                  event_id = schedule.find('aev:EventID', MINIMAL_VAPIX_NAMESPACES)
                  return None if event_id is None else event_id.text
         return None

      envelope = self.ListSchedules()
      for spec in schedule_specifications:
         if (schedule_id := name_to_id(envelope, spec['name'])) is not None:
            self.RemoveSchedule(schedule_id)
            if spec['event_id'] is None:
               spec['event_id'] = schedule_id

      result = []
      for spec in schedule_specifications:
         if spec['event_id'] is None:
            envelope = self._simple_vapix_webservice_call(AddScheduleXml.format(spec['name'], spec['ical_spec']))
         else:
            envelope = self._simple_vapix_webservice_call(AddScheduleWithIDXml.format(spec['name'], spec['event_id'], spec['ical_spec']))
         if (config := envelope.find('SOAP-ENV:Body/aev:AddScheduledEventResponse/aev:EventID', MINIMAL_VAPIX_NAMESPACES)) is None:
            result.append(spec['event_id'])
         else:
            result.append(config.text)
      return result

   def RemoveSchedule(self, event_id = '0'):
      """
      """
      req = RemoveScheduleXml.format(event_id)
      envelope = self._simple_vapix_webservice_call(req)
      success = envelope.find('SOAP-ENV:Body/aev:RemoveScheduledEventResponse', MINIMAL_VAPIX_NAMESPACES)
      return 'Failure' if success is None else 'Success'

   # ----------------------------------------------------------------------------
   # Recipients                                                              {{{3
   # ----------------------------------------------------------------------------

   # Recipients are a web GUI concept, you can configure action rules without
   # creating recipients on the device first

   def AddTCPRecipient(self, name, host, port, qos = 0):
      """
      Call: AddTCPRecipient(name,host,port,[qos])

      Add a TCP recipient to the event configuration
      """
      req = MakeRecipientConfiguration('com.axis.recipient.tcp', name, host=host, port=port, qos=qos)
      envelope = self._simple_vapix_webservice_call( req )
      return envelope.find('SOAP-ENV:Body/act:AddRecipientConfigurationResponse/act:ConfigurationID', MINIMAL_VAPIX_NAMESPACES).text

   def AddHTTPRecipient( self, name, url, usr='', passwd=''):
      """
      Call: AddHTTPRecipient(name,url,usr,passwd)

      Add a HTTP recipient to the event configuration
      """
      req = MakeRecipientConfiguration('com.axis.recipient.http', name, upload_url = url, login = usr, password = passwd)
      envelope = self._simple_vapix_webservice_call( req )
      return envelope.find('SOAP-ENV:Body/act:AddRecipientConfigurationResponse/act:ConfigurationID', MINIMAL_VAPIX_NAMESPACES).text

   def GetRecipientConfigurations(self):
      """
      Call: GetRecipientConfigurations

      (use -r)
      """
      self._simple_vapix_webservice_call( GET_RECIPIENT_CONFIGURATIONS )

   def RemoveRecipientConfiguration(self, recipient_id):
      """
      Call: RemoveRecipientConfiguration(recipient_id)
      """
      self._simple_vapix_webservice_call(REMOVE_RECIPIENT_CONFIGURATION.format(recipient_id))

   # ----------------------------------------------------------------------------
   # ActionConfigurations                                                    {{{3
   # ----------------------------------------------------------------------------

   def GetActionConfigurations(self):
      """
      Call: GetActionConfigurations

      (use -r)
      """
      return self._simple_vapix_webservice_call( GET_ACTION_CONFIGURATIONS )

   def RemoveActionConfiguration(self, action_id):
      """
      Call: RemoveActionConfiguration(action_id=integer)

      Remove an action configuration (make sure to remove the related
      ActionRule yourself)
      """
      return self._simple_vapix_webservice_call(REMOVE_ACTION_CONFIGURATION.format(action_id))

   def RemoveActionConfigurations(self):
      """
      Call: RemoveActionConfigurations

      Query the action configurations present on the device, and remove them
      one by one (make sure to remove the related ActionRules yourself)
      """
      envelope = self.GetActionConfigurations()
      ac_set = envelope.find('SOAP-ENV:Body/act:GetActionConfigurationsResponse/act:ActionConfigurations', MINIMAL_VAPIX_NAMESPACES)
      for ac in list(ac_set):
         ac_id = ac.find('act:ConfigurationID', MINIMAL_VAPIX_NAMESPACES)
         if ac_id is not None:
            envelope = self.RemoveActionConfiguration(ac_id.text)

   # ----------------------------------------------------------------------------
   # ActionRules                                                             {{{3
   # ----------------------------------------------------------------------------

   def GetActionRules(self):
      """
      Call: GetActionRules

      (use -r)
      """
      return self._simple_vapix_webservice_call(GET_ACTION_RULES)

   def RemoveActionRule(self, rule_id):
      """
      Call: RemoveActionRule(rule_id=integer)

      Remove an action rule. Does not remove the related action configuration!
      For that use RemoveActionRuleComplete() instead
      """
      self._simple_vapix_webservice_call(REMOVE_ACTION_RULE.format(rule_id))

   def RemoveActionRules(self):
      """
      Call: RemoveActionRules

      Query all action rules present on the device, and removed them one by
      one (does not remove related action configurations, make sure to call
      RemoveActionConfigurations() yourself)
      """
      envelope = self.GetActionRules()
      rule_set = envelope.find('SOAP-ENV:Body/act:GetActionRulesResponse/act:ActionRules', MINIMAL_VAPIX_NAMESPACES)
      for rule in list(rule_set):
         r_id = rule.find('act:RuleID', MINIMAL_VAPIX_NAMESPACES)
         if r_id is not None:
            self.RemoveActionRule(r_id.text)

   def RemoveActionRuleComplete(self, rule_id):
      """
      Call: RemoveActionRuleComplete(rule_id=integer)

      Remove an action rule including it's related action configuration. This
      function leaves the event configuration in a consistent state

      Get the rule_id's using GetActionRules
      """
      done = False
      envelope = self.GetActionRules()
      rule_set = envelope.find('SOAP-ENV:Body/act:GetActionRulesResponse/act:ActionRules', MINIMAL_VAPIX_NAMESPACES)
      for rule in list(rule_set):
         r_id = rule.find('act:RuleID', MINIMAL_VAPIX_NAMESPACES)
         if r_id is not None:
            if r_id.text == rule_id:
               action_id = rule.find('act:PrimaryAction', MINIMAL_VAPIX_NAMESPACES)
               self.RemoveActionRule(rule_id)
               if action_id is not None:
                  self.RemoveActionConfiguration(action_id.text)
               done = True
      return done

   #----------------------------------------------------------------------------
   # Input/Output, Digital I/O                                              {{{2
   #----------------------------------------------------------------------------

   def IOOn(self, output = 1):
      """
      Call: IOOn( output=output number )

      Set an output pin
      """
      return self._simple_vapix_call(f'/axis-cgi/io/port.cgi?action={output}%3A%2F')

   def IOOff(self, output = 1):
      """
      Call: IOOn( output=output number )

      Reset an output pin
      """
      return self._simple_vapix_call(f'/axis-cgi/io/port.cgi?action={output}%3A%5C')

   def VirtualIOOn(self, port = 1):
      """
      Call: VirtualIOOn(output=virtual port number)

      Set a virtualinput
      """
      return self._simple_vapix_call(f'/axis-cgi/virtualinput/activate.cgi?schemaversion=1&port={port}')

   def VirtualIOOff(self, port = 1):
      """
      Call: VirtualIOOff(output=virtual port number)

      Reset a virtualinput
      """
      return self._simple_vapix_call(f'/axis-cgi/virtualinput/deactivate.cgi?schemaversion=1&port={port}')

   def ManualTriggerOn(self):
      """
      Call: ManualTriggerOn

      Switch on the manual trigger
      """
      return self._simple_vapix_call('/axis-cgi/io/virtualinput.cgi?action=6%3A%2F')

   def ManualTriggerOff(self):
      """
      Call: ManualTriggerOff

      Switch off the manual trigger
      """
      return self._simple_vapix_call('/axis-cgi/io/virtualinput.cgi?action=6%3A%5C')


   def IOPulse(self, output = 1, duration = 1000):
      """
      Call: IOPulse( output=output number, duration=milliseconds

      Enable, wait, disable for an output pin
      """
      return self._simple_vapix_call(f'/axis-cgi/io/output.cgi?action={output}:/{duration}\\')

   #----------------------------------------------------------------------------
   # Analytics Metadata                                                     {{{2
   #----------------------------------------------------------------------------

   def ListProducers(self):
      return json.dumps(self._json_vapix_call(
         '/axis-cgi/analyticsmetadataconfig.cgi',
         MD_LIST_PRODUCERS
      ))

   def GetSupportedMetadata(self):
      response = self._json_vapix_call('/axis-cgi/analyticsmetadataconfig.cgi', MD_GET_SUPPORTED_METADATA)
      for example in response.get('data', {}).get('producers', []):
         print(f'\n{example["name"]}:')
         xml = ET.fromstring(example['sampleFrameXML'])
         xml_indent(xml)
         ET.dump(xml)
      return 'done'

   def GetSupportedVersions(self):
      return json.dumps(self._json_vapix_call(
         '/axis-cgi/analyticsmetadataconfig.cgi',
         GET_SUPPORTED_VERSIONS
      ))

   #----------------------------------------------------------------------------
   # MQTT Setup                                                             {{{2
   #----------------------------------------------------------------------------

   def MQTTActivate(self):
      return self._json_vapix_call('/axis-cgi/mqtt/client.cgi', MQTT_ACTIVATE_CLIENT)

   def MQTTDeactivate(self):
      return self._json_vapix_call('/axis-cgi/mqtt/client.cgi', MQTT_DEACTIVATE_CLIENT)

   def MQTTGetConfig(self):
      """
      Returns current broker configuration
      """
      return self._json_vapix_call('/axis-cgi/mqtt/client.cgi', MQTT_CLIENT_STATUS)

   def MQTTConfig(self, broker_usr = '', broker_passwd = '', broker_addr = '192.168.2.95',  broker_port = 1883):
      """
      Configure the MQTT Client on a device with a simple TCP based
      broker-connection. It takes care to not reconfigure if the settings are
      already in place

      Note: password will always be a mismatch :(
      """
      current_config = self.MQTTGetConfig()
      c = current_config['data']['config']
      if c['server']['host'] != broker_addr or \
         c['server']['port'] != broker_port or \
         c.get('username', '') != broker_usr or \
         c.get('password', '') != broker_passwd:

         c['server']['host'] = broker_addr
         c['server']['port'] = broker_port
         c['server']['protocol'] = 'tcp'
         c['username'] = broker_usr
         c['password'] = broker_passwd
         self._json_vapix_call('/axis-cgi/mqtt/client.cgi', JSON_REQUEST.format('1.0', 'configureClient', json.dumps(c)))
         return self.MQTTActivate()
      return 'No change'

   def MQTTRemoveEventPublications(self):
      return self.MQTTAddEventPublications([])

   def MQTTGetEventPublications(self):
      """
      Get the current event publications
      """
      response = self._json_vapix_call('/axis-cgi/mqtt/event.cgi', '{"apiVersion":"1.1","method":"getEventPublicationConfig"}')
      return response['data']['eventPublicationConfig']['eventFilterList']

   def MQTTAddEventPublications(self, topic_filter_list : list[str]):
      publications_request = {
         "apiVersion": "1.1",
         "method": "configureEventPublication",
         "params": {
            "topicPrefix": "default",
            "customTopicPrefix": "",
            "appendEventTopic": True,
            "includeSerialNumberInPayload": False,
            "includeTopicNamespaces":True,
            "eventFilterList": topic_filter_list
         }
      }
      return self._json_vapix_call('/axis-cgi/mqtt/event.cgi', json.dumps(publications_request))

   def MQTTAddEventPublication(self, topic_filter : str = 'onvif:AudioSource/axis:TriggerLevel', retain : str = 'none', qos : int = 0):
      publications = self.MQTTGetEventPublications()
      if topic_filter not in publications:
         publications.append({'topicFilter': topic_filter, 'retain': retain, 'qos': qos})
         return self.MQTTAddEventPublications(publications)
      else:
         return 'No change'

   #----------------------------------------------------------------------------
   # IEEE 802.1X                                                            {{{2
   #----------------------------------------------------------------------------

   def _set_dot1x_config(self, config):
      """
      Applies IEEE 802.1x config from internal data structure
      """
      CACERTSPEC = '<tt:CACertificateID>{}</tt:CACertificateID>'
      cacert_spec = ''.join([CACERTSPEC.format(name) for name in config['ca_certs']])

      self._simple_vapix_webservice_call(SetDot1XConfigXml.format(
         token = 'EAPTLS_WIRED',
         mac = config['serial'],
         method = config['eap_method'],
         certname = config['client_cert'],
         cacert_spec = cacert_spec
      ))

      # TODO: check webservice response?

      return self._json_vapix_call(
         '/axis-cgi/network_settings.cgi',
         JSON_REQUEST.format(
            '1.15',
            'setWired8021XConfiguration',
            '{{"deviceName":"eth0","eapolVersion":"EAPoLv2","enabled":true,"identity":"{}","mode":"WPA-Enterprise-EAPTLS"}}'.format(dotx_conf['serial'])
         )
      )

   def GetDot1XConfiguration(self):
      """
      Get the IEEE 802.1x configuration
      """
      envelope = self._simple_vapix_webservice_call(GetDot1XConfigXml.format(
         token = 'EAPTLS_WIRED',
      ))
      if (conf := envelope.find('SOAP-ENV:Body/tds:GetDot1XConfigurationResponse/tds:Dot1XConfiguration', MINIMAL_VAPIX_NAMESPACES)) is not None:
         dotx_conf = {
            'ca_certs': []
         }
         for ca in conf.findall('tt:CACertificateID', MINIMAL_VAPIX_NAMESPACES):
           dotx_conf['ca_certs'].append(ca.text)
         dotx_conf['eap_method'] = conf.find('tt:EAPMethod', MINIMAL_VAPIX_NAMESPACES).text
         dotx_conf['client_cert'] = conf.find('tt:EAPMethodConfiguration/tt:TLSConfiguration/tt:CertificateID', MINIMAL_VAPIX_NAMESPACES).text
         return dotx_conf
      return None

   def SetDot1XConfiguration(self, certname = 'X', cacert1name = 'Y', cacert2name = None):
      """
      Configure certificate-based port authentication with 1 or 2 certs for
      evaluating RADIUS server certificate
      """
      dot1x_conf = {
         'ca_certs': [ cacert1name ],
         'serial': self.GetSerialNumber(),
         'eap_method': '13',
         'client_cert': certname
      }
      if cacert2name:
         dot1x_conf['ca_certs'].append(cacert2name)

      return self._set_dot1x_config(dot1x_conf)

   def AddDot1XCACertName(self, cacert_name):
      """
      Add another CA Cert for RADIUS server cert verification. This function
      aids in making no mistakes:

      - It checks for existance of the CA cert with name <cacert_name>
      - It checks whether the config isn't already using <cacert_name>

      Pre:
      - The device should already have a valid IEEE 802.1X configuration
      """
      cacert_names = self.GetCACertificateNames()
      dot1x_conf = self.GetDot1XConfiguration()

      if cacert_name not in cacert_names:
         return f'Failed: No CA certificate present with name {cacert_name}'

      if cacert_name in dot1x_conf['ca_certs']:
         return f'Failed: CA certificate {cacert_name} is already used for RADIUS verification'

      dot1x_conf['ca_certs'].append(cacert_name)
      dot1x_conf['serial'] = self.GetSerialNumber()
      self._set_dot1x_config(dot1x_conf)
      return 'Done'

   def RemoveDot1XCACertName(self, cacert_name):
      """
      Remove <cacert_name> from the list of CA certs for RADIUS verification,
      as long some other certificate remains
      """
      dot1x_conf = self.GetDot1XConfiguration()

      if cacert_name not in dot1x_conf['ca_certs']:
         return f'Failed: CA certificate {cacert_name} is not used for RADIUS verification'

      if len(dot1x_conf['ca_certs']) <= 1:
         return f'Failed: No other CA certificate would remain'

      dot1x_conf['ca_certs'].remove(cacert_name)
      dot1x_conf['serial'] = self.GetSerialNumber()
      self._set_dot1x_config(dot1x_conf)
      return 'Done'

   def GetCACertificateNames(self):
      """
      Get the certificates and print the names
      """
      names = []
      envelope = self._simple_vapix_webservice_call(GetCACertificatesXml)
      for cert in list(envelope.find('SOAP-ENV:Body/tds:GetCACertificatesResponse', MINIMAL_VAPIX_NAMESPACES)):
         if (the_id := cert.find('tt:CertificateID', MINIMAL_VAPIX_NAMESPACES)) is not None:
            names.append(the_id.text)
      return names

   def DeleteCertificate(self, cert_name):
      """
      Remove a certiticate. This function uses the webservice API, newer
      devices have a Decaf API:
      http://192.168.200.13/config/rest/cert/v1/ca_certificates/,cert_id>
      """
      return self._simple_vapix_webservice_call(DeleteCertificate.format(cert_name))

   def LoadCACertificate(self, filename):
      """
      Load a CA Certificate. The filename without extension is used
      as Certificate ID
      """
      if not os.path.exists(filename):
         return f'Failed: {filename} not found'

      basename = os.path.basename(filename)
      title = os.path.splitext(basename)[0]

      with open(filename, 'rt') as f:
         lines = f.readlines()

      if lines[0] != '-----BEGIN CERTIFICATE-----\n':
         return f'Failed: {filename} has unexpected content'

      return self._simple_vapix_webservice_call(
            LoadCACertificatesXml.format(cert_id = title, body = ''.join(lines[1:-1]))
         )

# -------------------------------------------------------------------------------
#
#   Other                                                                   {{{1
#
# -------------------------------------------------------------------------------

class MyUsecases(VapixClient):
   """
   Non-generic calls which don't make sense to include in base VapixClient
   """

   def _add_action_rule(self, actionrule_name, schedule_id_a, schedule_id_b, start_event, play_clip_name, use_virtual_input: bool = False):
      """
      Implements the core logic for the ActionRuleTest_* functions
      """
      # Note! Older Axis OS expects audioclip with path, later ones without path?
      envelope = self._simple_vapix_webservice_call(MakeActionConfiguration('com.axis.action.fixed.play.audioclip', play_clip_name, location = '/etc/audioclips/camera_clicks16k.au'))
      if (config := envelope.find('SOAP-ENV:Body/act:AddActionConfigurationResponse/act:ConfigurationID', MINIMAL_VAPIX_NAMESPACES)) is not None:

         conditions = ConditionList()
         conditions.add(
            topic = 'tns1:UserAlarm/tnsaxis:Recurring/Interval',
            content_filter = f'boolean(//SimpleItem[@Name="id" and @Value="{schedule_id_a}"]) and boolean(//SimpleItem[@Name="active" and @Value="0"])'
         )
         conditions.add(
            topic = 'tns1:UserAlarm/tnsaxis:Recurring/Interval',
            content_filter = f'boolean(//SimpleItem[@Name="id" and @Value="{schedule_id_b}"]) and boolean(//SimpleItem[@Name="active" and @Value="0"])'
         )
         if use_virtual_input:
            # Combine with a virtual input (to try silence the event on
            # schedule-modifications)
            conditions.add(
               topic = 'tns1:Device/tnsaxis:IO/VirtualInput',
               content_filter = 'boolean(//SimpleItem[@Name="port" and @Value="9"]) and boolean(//SimpleItem[@Name="active" and @Value="1"])'
            )
         req = GenericActionRule.format(
            actionrule_name,
            start_event.serialize(),
            conditions.serialize(),
            config.text
         )
         envelope = self._simple_vapix_webservice_call(req)
         config = envelope.find('SOAP-ENV:Body/act:AddActionRuleResponse/act:RuleID', MINIMAL_VAPIX_NAMESPACES)
         if config is not None:
            return config.text
      return None

   def ActionRuleTest(self, start_event):
      """
      Configure two rules to Play audio clip triggered by 'start_event', when
      when two schedules are not active. Inspired by a specific troubleshoot
      but usefull as general example for configuring event rules.

      Pre: start with clean (empty) eventrule configuration
      """
      schedule_id1, schedule_id2, schedule_id3, schedule_id4 = self.AddOrModifySchedules1()


      ids = [
         self._add_action_rule('Play a clip 1', schedule_id1, schedule_id2, start_event, 'Play my clip 1'),
         self._add_action_rule('Play a clip 2', schedule_id3, schedule_id4, start_event, 'Play my clip 2')
      ]

      return ids

   def ActionRuleTest_byCallButton(self):
      """
      Configure the rule with Call button pressed (= input 0 toggles) as start
      event
      """
      start_event = StartEvent(
         'tns1:Device/tnsaxis:IO/Port',
         'boolean(//SimpleItem[@Name="port" and @Value="0"]) and boolean(//SimpleItem[@Name="state" and @Value="1"])'
      )
      return self.ActionRuleTest(start_event)

   def ActionRuleTest_byManualTrigger(self):
      """
      Configure the rule with Manual Trigger pressed as start event

      Seems a bit of an oddity that we need to listen to port 1 while we need
      to set virtual port 6 to trigger it
      """
      start_event = StartEvent(
         'tns1:Device/tnsaxis:IO/VirtualPort',
         'boolean(//SimpleItem[@Name="port" and @Value="1"]) and boolean(//SimpleItem[@Name="state" and @Value="1"])'
      )
      return self.ActionRuleTest(start_event)

   def AddOrModifySchedules1(self):
      """
      (Re-)defines the schedule in use by the action-rule created by
      ActionRuleTest()
      """
      return self.AddOrReplaceSchedules([
         # 800
         {'name': 'My Schedule 1', 'event_id': None, 'ical_spec': 'DTSTART:19700101T000000\nDTEND:19700101T080000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # 801
         {'name': 'My Schedule 2', 'event_id': None, 'ical_spec': 'DTSTART:19700101T161000\nDTEND:19700101T163500\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # 900
         {'name': 'My Schedule 3', 'event_id': None, 'ical_spec': 'DTSTART:19700101T080000\nDTEND:19700101T161000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # 901
         {'name': 'My Schedule 4', 'event_id': None, 'ical_spec': 'DTSTART:19700101T163500\nDTEND:19700101T235959\nRRULE:FREQ=WEEKLY;BYDAY=FR'}
      ])

   def AddOrModifySchedules2(self):
      """
      (Re-)defines the schedule in use by the action-rule created by
      ActionRuleTest()
      """
      return self.AddOrReplaceSchedules([
         # 800
         {'name': 'My Schedule 1', 'event_id': None, 'ical_spec': 'DTSTART:19700101T000000\nDTEND:19700101T080000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # Weekdays
         {'name': 'My Schedule 2', 'event_id': None, 'ical_spec': 'DTSTART:19700105T000000\nDTEND:19700110T000000\nRRULE:FREQ=WEEKLY'},
         # 900
         {'name': 'My Schedule 3', 'event_id': None, 'ical_spec': 'DTSTART:19700101T080000\nDTEND:19700101T161000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # Office hours
         {'name': 'My Schedule 4', 'event_id': None, 'ical_spec': 'DTSTART:19700101T080000\nDTEND:19700101T180000\nRRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR'}
      ])

   def AddOrModifySchedules3(self):
      """
      (Re-)defines the schedule in use by the action-rule created by
      ActionRuleTest()
      """
      return self.AddOrReplaceSchedules([
         # 800
         {'name': 'My Schedule 1', 'event_id': None, 'ical_spec': 'DTSTART:19700101T000000\nDTEND:19700101T080000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # Weekends
         {'name': 'My Schedule 2', 'event_id': None, 'ical_spec': 'DTSTART:19700103T000000\nDTEND:19700105T000000\nRRULE:FREQ=WEEKLY'},
         # 900
         {'name': 'My Schedule 3', 'event_id': None, 'ical_spec': 'DTSTART:19700101T080000\nDTEND:19700101T161000\nRRULE:FREQ=WEEKLY;BYDAY=FR'},
         # After hours
         {'name': 'My Schedule 4', 'event_id': None, 'ical_spec': 'DTSTART:19700101T180000\nDTEND:19700102T080000\nRRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR'}
      ])

   def SetupSytemReadyMessage(self, name, recipient_name, url, usr='', passwd='', message='', parameters = ''):
      """
      Add Event Rule for sending out a HTTP notification on SystemReady

      - Create event action
      - Find the id of the new event action in the response
      - Create event rule with the trigger condition, pointing to the action
        id
      """
      envelope = self._simple_vapix_webservice_call(
         MakeActionConfiguration(
            'com.axis.action.fixed.notification.https',
            recipient_name,
            upload_url = url,
            login = usr,
            password = passwd,
            message = message,
            parameters = parameters
         )
      )
      config = envelope.find('SOAP-ENV:Body/act:AddActionConfigurationResponse/act:ConfigurationID', MINIMAL_VAPIX_NAMESPACES)
      if config != None:
         action_config_id = config.text
         conditions = ConditionList()
         conditions.add(
            topic = 'tns1:Device/tnsaxis:Status/SystemReady',
            content_filter = 'boolean(//SimpleItem[@Name="ready" and @Value="1"])'
         )
         req = GenericActionRule.format(
            name,
            '',
            conditions.serialize(),
            action_config_id
         )

         envelope = self._simple_vapix_webservice_call( req )
         config = envelope.find('SOAP-ENV:Body/act:AddActionRuleResponse/act:RuleID', MINIMAL_VAPIX_NAMESPACES)
         if config != None:
            return config.text
      return None

   def MySystemReady(self):
      return self.SetupSytemReadyMessage(
         name = 'System is up',
         recipient_name = 'self',
         url = 'https://127.0.1.1/axis-cgi/virtualinput/activate.cgi',
         usr = 'root',
         passwd = 'pass',
         message = 'test',
         parameters = 'schemaversion=1&amp;port=11'
      )

# -------------------------------------------------------------------------------
#
#   Main                                                                    {{{1
#
# -------------------------------------------------------------------------------

class Executor:
   """
   A class to assemble the list of functions to call, and runnning the requested sequence
   """
   def __init__(self, args, interface: Type[VapixClient]):
      self.args = args
      self.clients = {}
      self.iteration_counter = 0
      self.interface = interface
      self.tool_list = interface.functions()
      for cam in args.camera:
         w = WebAccess(cam, context = StandardSSLContext())
         w.add_credentials(args.user, args.password)
         self.clients[cam] = interface(w, args.raw)

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
            if name in self.tool_list:
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
               elif isinstance(r, ET.Element):
                  xml_indent(r)
                  ET.dump(r)
                  sys.stdout.flush()
               else:
                  pprint.pprint(r)
            else:
               print('No such function:', name)
            if self.args.sleep1:
               print(f'Sleep for {self.args.sleep1} seconds')
               time.sleep(float(self.args.sleep1))


if __name__ == '__main__':

   def read_config() -> configparser.ConfigParser:
      """
      If present, read data from .eap_install.cfg so that it can be used to
      populate default argument values
      """
      config = configparser.ConfigParser(interpolation=None)
      config['default'] = {}
      config['default']['user'] = 'root'
      config['default']['password'] = 'pass'

      eap_info = '.eap-install.cfg'
      if os.path.isfile(eap_info):
         settings = '[default]\n'
         with open(eap_info, 'r', encoding='utf-8') as _f:
            settings += _f.read()
         config.read_string(settings)
      return config

   def create_parser(config: configparser.ConfigParser, interface: VapixClient) -> argparse.ArgumentParser:
      """
      Define the commandline. It picks default values from 'config'
      """
      p = argparse.ArgumentParser(
         description = 'Collection of commands to interact with Axis cameras.\nCommands can be run in sequence with wait times in between',
         formatter_class = argparse.RawDescriptionHelpFormatter,
         epilog = 'Functions:\n{}\n\n'.format('\n'.join(interface.functions()))
      )

      p.add_argument(
           '-c', '--camera', type = str, action='append',
           help='Hostname/IP address of the device(s) to interact with. You can specify multiple cameras')
      p.add_argument(
           '-u', '--user', type = str, default = config['default']['user'],
           help = f'username to login with ({config["default"]["user"]})')
      p.add_argument(
           '-p', '--password', type = str, default = config['default']['password'],
           help = f'password to login with ({config["default"]["password"]})')
      p.add_argument(
           '-x', '--proxy', type = str, default = None,
           help = 'proxy to use, e.g. "http://user:pass@proxyaddr:proxyport" (none)')
      p.add_argument(
           '-f', '--function', action = 'append',
           help = 'Function to call. You can specify multiple -f arguments')
      p.add_argument(
           '-d', '--document', action ='store_true',
           help = 'Get detailed documentation on calling a function')
      p.add_argument(
           '-r', '--raw', action = 'store_true',
           help = 'Output raw data instead of processed response only (some functions always dump raw response)')
      p.add_argument(
           '-i', '--iterations', type = int, default = -1,
           help = 'How many times to repeat the requests (no repetition). 0 repeats endless')
      p.add_argument(
           '-s', '--sleep1', type = int, default = 0,
           help = 'Sleeptime between functions (0)')
      p.add_argument(
           '-S', '--sleep2', type = int, default = 7200,
           help = 'Sleeptime between iterations (7200)')
      return p


   def main():
      """
      Pre-check some arguments and pass on to Executor-instance
      """
      config = read_config()
      # interface = VapixClient
      # Or..
      interface = MyUsecases
      tool_list = interface.functions()
      parser = create_parser(config, interface)
      args = parser.parse_args()
      if args.camera is None:
         if 'axis_device_ip' in config['default']:
            args.camera = [ config['default']['axis_device_ip'] ]
      if args.function is None or (args.camera is None and not args.document):
         parser.print_usage()
         sys.exit(2)
      # If requested, show documentation and exit
      if args.document:
         for func in args.function:
            if func in tool_list:
               print(getattr(interface, func).__doc__)
            else:
               print(f'Unsupported: {func}')
         sys.exit(0)

      Executor(args, interface).run()

   main()

#  vim: set nowrap sw=3 sts=3 et fdm=marker:
