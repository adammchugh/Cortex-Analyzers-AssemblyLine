#!/usr/bin/env python3
# encoding: utf-8

import time

from cortexutils.analyzer import Analyzer
from assemblyline_client import get_client

class Assemblyline(Analyzer):

  def __init__(self):
    Analyzer.__init__(self)
    self.service = self.get_param('config.service', None, 'Service parameter is missing')
    self.polling_interval = self.get_param('config.polling_interval', 60)
    self.proxies = self.get_param('config.proxy', None)
    self.assemblyline_server = self.get_param('config.assemblyline_server',None)
    self.assemblyline_user = self.get_param('config.assemblyline_user',None)
    self.assemblyline_key = self.get_param('config.assemblyline_key',None)
    self.assemblyline_verifyssl = self.get_param('config.assemblyline_verifyssl',True)

  def artifacts(self, raw):
    return [self.build_artifact(self.data_type, self.getData(), tags=["assemblyline"], tlp=self.tlp)]

  def run(self):
    if self.data_type not in ['file']:
      self.notSupported()

    al_client = get_client(self.assemblyline_server, apikey=(self.assemblyline_user, self.assemblyline_key), verify=self.assemblyline_verifyssl)
    al_client.submit('/path/to/my/file.txt')

    time.sleep(self.getParam("config.delay", 60))

    self.report({'data': self.getData(), 'input': self._input})

  def summary(self, raw):
    return {'taxonomies': [self.build_taxonomy('info', 'assemblyline', self.data_type, self.getData())]}

if __name__ == '__main__':
  Assemblyline().run()
