#!/usr/bin/env python3
#--------------------------------------------- ghislain.bernard@gmail.com ---------------------------------------------#

import time

from cortexutils.analyzer import Analyzer

#----------------------------------------------------------------------------------------------------------------------#

class Template(Analyzer):

  def __init__(self):
    Analyzer.__init__(self)

  def artifacts(self, raw):
    return [self.build_artifact(self.data_type, self.getData(), tags=["template"], tlp=self.tlp)]

  def run(self):
    if self.data_type not in ['domain', 'ip']:
      self.notSupported()

    time.sleep(self.getParam("config.delay", 60))

    self.report({'data': self.getData(), 'input': self._input})

  def summary(self, raw):
    return {'taxonomies': [self.build_taxonomy('info', 'template', self.data_type, self.getData())]}

#----------------------------------------------------------------------------------------------------------------------#

if __name__ == '__main__':
  Template().run()

#--------------------------------------------- ghislain.bernard@gmail.com ---------------------------------------------#
