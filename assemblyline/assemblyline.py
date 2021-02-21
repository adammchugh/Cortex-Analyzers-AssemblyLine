#!/usr/bin/env python3
# encoding: utf-8

import time
import assemblyline

from cortexutils.analyzer import Analyzer

class Assemblyline(Analyzer):

  def __init__(self):
    Analyzer.__init__(self)
    self.service = self.get_param('config.service', None, 'Service parameter is missing')
    self.polling_interval = self.get_param('config.polling_interval', 60)
    self.proxies = self.get_param('config.proxy', None)

  def artifacts(self, raw):
    return [self.build_artifact(self.data_type, self.getData(), tags=["assemblyline"], tlp=self.tlp)]

  def run(self):
    if self.data_type not in ['domain', 'ip']:
      self.notSupported()

    time.sleep(self.getParam("config.delay", 60))

    self.report({'data': self.getData(), 'input': self._input})

  def summary(self, raw):
    return {'taxonomies': [self.build_taxonomy('info', 'assemblyline', self.data_type, self.getData())]}

if __name__ == '__main__':
  Assemblyline().run()
