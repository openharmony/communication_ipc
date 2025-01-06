#!/usr/bin/env python3
# coding=utf-8

#
# Copyright (C) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import os
sys.path.insert(0, os.environ.get('PYTEST_PYTESTPATH'))
import unittest
from distributed import *

class DbinderTest(unittest.TestCase):
    def setUp(self):
        print('setUp')
        self.result_path = get_result_dir(__file__)
        self.suits_dir = os.path.abspath(os.path.dirname(__file__))
        self.manager = DeviceManager()
        self.major = self.manager.PHONE1
        self.agent_list = [self.manager.PHONE2]

    def test_dbinder(self):
        major_target_name = "DbinderTest"
        agent_target_name = "DbinderTestAgent"

        distribute = Distribute(self.suits_dir, self.major, self.agent_list)

        for agent in self.agent_list:
            if not distribute.exec_agent(agent, agent_target_name):
                create_empty_result_file(self.result_path, major_target_name)
                return

        distribute.exec_major(self.major, major_target_name)

        source_path = "%s/%s.xml" % (self.major.test_path, major_target_name)
        distribute.pull_result(self.major, source_path, self.result_path)

    def tearDown(self):
        print('tearDown')


if __name__ == '__main__':
    unittest.main()
