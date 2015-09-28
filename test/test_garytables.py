#!/usr/bin/python
# The MIT License (MIT)
# 
# Copyright (C) 2015, Sam Russell <sam.h.russell@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person 
# obtaining a copy of this software and associated documentation 
# files (the "Software"), to deal in the Software without 
# restriction, including without limitation the rights to use, 
# copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following 
# conditions: 
# 
# The above copyright notice and this permission notice shall be 
# included in all copies or substantial portions of the Software. 
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
# OTHER DEALINGS IN THE SOFTWARE.

from unittest import TestCase
import mock

def test_urls():
  iptc_mock = mock.MagicMock()
  modules = {
    'iptc' : iptc_mock
  }
  mock.module_patcher = mock.patch.dict('sys.modules', modules)
  mock.module_patcher.start()
  from garytables import garytables

  assert garytables.API10.get_table_list_url() == '/api/v1.0/table'
  assert garytables.API10.get_table_url('filter') == '/api/v1.0/table/filter/chain'
  assert garytables.API10.get_chain_url('filter', 'input') == '/api/v1.0/table/filter/chain/input/rule'
  assert garytables.API10.get_rule_url('filter', 'input', 3) == '/api/v1.0/table/filter/chain/input/rule/3'


