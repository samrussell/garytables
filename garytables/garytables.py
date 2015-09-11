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

import flask, iptc, json

app = flask.Flask(__name__)

# do table names in uppercase, this is what we'll query iptc with
TABLES = ['FILTER']
FILTER_CHAINS = ['INPUT', 'OUTPUT', 'FORWARD']
TABLE_CHAINS = { 'FILTER' : FILTER_CHAINS }
TARGETS = ['ACCEPT', 'DROP']

class Rule:

    def __init__(self, num=None, in_interface=None, out_interface=None, src=None, dst=None, protocol=None, target=None):
        self.num = num
        self.in_interface = in_interface
        self.out_interface = out_interface
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.target = target

    @staticmethod
    def build_from_iptables(rule, rule_num):
        rule_dict = {}
        rule_dict['num'] = rule_num
        rule_dict['target'] = rule.target.name
        # handle logic for table/chain-specific stuff (can do this better
        # example: in_interface is only valid for INPUT chain in FILTER table
        if rule.in_interface:
            rule_dict['in_interface'] = rule.in_interface
        if rule.out_interface:
            rule_dict['out_interface'] = rule.out_interface
        rule_dict['protocol'] = rule.protocol
        rule_dict['src'] = rule.src
        rule_dict['dst'] = rule.dst
        # should return a Rule class
        return Rule(**rule_dict)

    def write_to_iptables(self, table_name, chain_name):
        table = iptc.Table(table_name.lower())
        table.refresh()
        chains_by_name = {chain.name : chain for chain in table.chains}
        chain = chains_by_name[chain_name.upper()]
        rule = iptc.Rule()
        if self.in_interface:
            rule.in_interface = self.in_interface
        if self.out_interface:
            rule.out_interface = self.out_interface
        if self.src:
            rule.src = self.src
        if self.dst:
            rule.dst = self.dst
        if self.protocol:
            rule.protocol = self.protocol
        else:
            rule.protocol = 'ip'
        rule.target = iptc.Target(rule, self.target)
        chain.insert_rule(rule)

def parse_iptc_rule_to_dict(rule, rule_num):
    rule_dict = {}
    rule_dict['num'] = rule_num
    rule_dict['target'] = rule.target.name
    # handle logic for table/chain-specific stuff (can do this better
    # example: in_interface is only valid for INPUT chain in FILTER table
    if rule.in_interface:
        rule_dict['in_interface'] = rule.in_interface
    if rule.out_interface:
        rule_dict['out_interface'] = rule.out_interface
    rule_dict['protocol'] = rule.protocol
    rule_dict['src'] = rule.src
    rule_dict['dst'] = rule.dst
    return rule_dict


def get_iptables_rules_from_chain(table_name, chain_name):
    table = iptc.Table(table_name.lower())
    table.refresh()
    chains_by_name = {chain.name : chain for chain in table.chains}
    chain = chains_by_name[chain_name.upper()]
    rules = [parse_iptc_rule_to_dict(rule, rule_num) for rule_num, rule in enumerate(chain.rules)]
    return rules

def add_iptables_rule_to_chain(table_name, chain_name, json_input):
    # it would be better to have a class for rules that does sanity checking...
    table = iptc.Table(table_name.lower())
    table.refresh()
    chains_by_name = {chain.name : chain for chain in table.chains}
    chain = chains_by_name[chain_name.upper()]
    rule = iptc.Rule()
    if 'in_interface' in json_input:
        rule.in_interface = json_input['in_interface']
    if 'out_interface' in json_input:
        rule.out_interface = json_input['out_interface']
    if 'src' in json_input:
        rule.src = json_input['src']
    if 'dst' in json_input:
        rule.src = json_input['dst']
    if 'protocol' in json_input:
        rule.protocol = json_input['protocol']
    else:
        rule.protocol = 'ip'
    rule.target = iptc.Target(rule, json_input['target'])
    chain.insert_rule(rule)

class API10:
    TABLE_LIST_URL = '/table'
    TABLE_URL = '/table/%(table_name)s'
    CHAIN_LIST_URL = '/table/%(table_name)s/chain'
    CHAIN_URL = '/table/%(table_name)s/chain/%(chain_name)s'
    RULE_LIST_URL = '/table/%(table_name)s/chain/%(chain_name)s/rule'
    RULE_URL = '/table/%(table_name)s/chain/%(chain_name)s/rule/%(rule_num)d'

    @staticmethod
    def get_table_list_url():
        return API10.TABLE_LIST_URL

    @staticmethod
    def get_table_url(table_name):
        return API10.TABLE_URL % {'table_name' : table_name}

    @staticmethod
    def get_chain_list_url(table_name):
        return API10.CHAIN_LIST_URL % {'table_name' : table_name}

    @staticmethod
    def get_table_url(table_name, chain_name):
        return API10.CHAIN_URL % {'table_name' : table_name,
                                  'chain_name' : chain_name,
                                  }

class RestfulObject:

    def __init__(self):
        self.response = {}

    def to_rest_response(self):
        return json.dumps(self.response)

class IptablesTableList10(RestfulObject):

    def __init__(self):
        super(IptablesTableList, self).__init__()
    

class IptablesTable10(RestfulObject):
    pass

class IptablesChain10(RestfulObject):
    pass

@app.route('/api/v1.0/table', methods=['GET'])
def show_tables():
    return flask.jsonify({'tables' : TABLES})

@app.route('/api/v1.0/table/<table_name>/chain', methods=['GET'])
def show_chains(table_name):
    if table_name.upper() not in TABLES:
        flask.abort(400)
    return flask.jsonify(
                        {
                        'table' : {
                            'name' : table_name,
                            'chains' : TABLE_CHAINS[table_name.upper()],
                            }
                        })

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule', methods=['GET'])
def show_rules(table_name, chain_name):
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules = get_iptables_rules_from_chain(
                table_name, chain_name)
    return flask.jsonify(
                        {
                        'table' : {
                            'name' : table_name,
                            'chain' : {
                                'name' : chain_name,
                                'rules' : rules,
                                }
                            }
                        })

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule/<int:rule_num>', methods=['GET'])
def show_rule_by_num(table_name, chain_name, rule_num):
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules = get_iptables_rules_from_chain(
                table_name, chain_name)
    if rule_num < 0 or rule_num > (len(rules)-1):
        flask.abort(400)
    rule = rules[rule_num]
    if rule['num'] != rule_num:
        flask.abort(400)
    return flask.jsonify(
                        {
                        'table' : {
                            'name' : table_name,
                            'chain' : {
                                'name' : chain_name,
                                'rule' : rule,
                                }
                            }
                        })

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule', methods=['POST'])
def add_rule(table_name, chain_name):
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    if not flask.request.json:
        flask.abort(400)

    add_iptables_rule_to_chain(table_name, chain_name, flask.request.json)
    return flask.jsonify(
                        {
                        'table' : {
                            'name' : table_name,
                            'chain' : {
                                'name' : chain_name,
                                'rule' : flask.request.json,
                                }
                            }
                        })

def main():
    app.debug = True
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
