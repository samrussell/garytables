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

import flask, iptc

app = flask.Flask(__name__)

# do table names in uppercase, this is what we'll query iptc with
TABLES = ['FILTER']
FILTER_CHAINS = ['INPUT', 'OUTPUT', 'FORWARD']
TABLE_CHAINS = { 'FILTER' : FILTER_CHAINS }
TARGETS = ['ACCEPT', 'DROP']

def parse_iptc_rule_to_dict(rule):
    rule_dict = {}
    rule_dict['target'] = rule.target.name
    # handle logic for table/chain-specific stuff (can do this better
    # example: in_interface is only valid for INPUT chain in FILTER table
    if rule.in_interface:
        rule_dict['in_interface'] = rule.in_interface
    if rule.out_interface:
        rule_dict['out_interface'] = rule.out_interface
    protocol = rule.protocol
    if protocol == 'ip':
        protocol = 'all'
    rule_dict['protocol'] = protocol
    rule_dict['src'] = rule.src
    rule_dict['dst'] = rule.dst
    return rule_dict


def get_iptables_rules_from_chain(table_name, chain_name):
    table = iptc.Table(table_name.lower())
    table.refresh()
    chains_by_name = {chain.name : chain for chain in table.chains}
    chain = chains_by_name[chain_name.upper()]
    rules = [parse_iptc_rule_to_dict(rule) for rule in chain.rules]
    return rules

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

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>', methods=['GET'])
def show_rules(table_name, chain_name):
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules = get_iptables_rules_from_chain(
                table_name, chain_name),
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

def main():
    app.debug = True
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
