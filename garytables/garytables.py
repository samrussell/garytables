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

import flask, iptc, json, pprint, hashlib, threading, functools

lock_access_iptc = threading.Lock()

app = flask.Flask(__name__)

# do table names in uppercase, this is what we'll query iptc with
TABLES = ['FILTER']
FILTER_CHAINS = ['INPUT', 'OUTPUT', 'FORWARD']
TABLE_CHAINS = { 'FILTER' : FILTER_CHAINS }
TARGETS = ['ACCEPT', 'DROP']

class Rule:
    """
    This class represents an iptables Rule

    A Rule consists of a set of parameters to match on, and a target.
    Currently, the following parameters are supported:

    - Interface (in and out)
    - IP address (source and destination)
    - Protocol (only IP)
    
    All targets are currently supported, with no per-chain sanity checking

    """

    def __init__(
            self, rule_num=None, in_interface=None, out_interface=None,
            src=None, dst=None, protocol=None, target=None):
        self.rule_num = rule_num
        self.in_interface = in_interface
        self.out_interface = out_interface
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.target = target

    @staticmethod
    def build_from_iptables(rule, rule_num):
        """
        Factory to make a new Rule from a python-iptables Rule

        :param rule: An iptc.Rule object
        :param rule_num: The index of the rule in the list (starts with 1)
        :returns: A garytables.Rule object, equivalent to param 'rule'
        """
        rule_dict = {}
        rule_dict['rule_num'] = rule_num
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
        """
        Writes this Rule to iptables

        :param table_name: Name of the table to write to
        :param chain_name: Name of the chain to write to
        """
        with lock_access_iptc:
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

    def get_dict(self):
        """
        Returns a dictionary of fields, for a REST response

        :returns: a dictionary of fields
        """
        response = {}
        if self.rule_num:
            response['rule_num'] = self.rule_num
        if self.in_interface:
            response['in_interface'] = self.in_interface
        if self.out_interface:
            response['out_interface'] = self.out_interface
        if self.src:
            response['src'] = self.src
        if self.dst:
            response['dst'] = self.dst
        if self.protocol:
            response['protocol'] = self.protocol
        if self.target:
            response['target'] = self.target
        return response

    def get_etag(self):
        """
        Generates an etag for this Rule to allow optimistic locking

        :returns: a (ideally) UUID string for this Rule
        """
        rule_dict_string = pprint.pformat(self.get_dict())
        etag_hash = hashlib.sha256(rule_dict_string).hexdigest()
        return etag_hash

def get_iptables_rules_from_chain(table_name, chain_name):
    """
    Gets the iptables rules from a chain

    :param table_name: Name of the iptables table
    :param chain_name: Name of the iptables chain within table_name
    :returns: A list of rules
    """
    with lock_access_iptc:
        table = iptc.Table(table_name.lower())
        table.refresh()
        chains_by_name = {chain.name : chain for chain in table.chains}
        chain = chains_by_name[chain_name.upper()]
        # this might not need to be locked, but will confirm this later
        rules = [Rule.build_from_iptables(rule, rule_num) for rule_num, rule in enumerate(chain.rules, start=1)]
    return rules

def get_iptables_rules_from_chain_by_number(table_name, chain_name):
    """
    Gets the iptables rules from a chain, with line numbers

    :param table_name: Name of the iptables table
    :param chain_name: Name of the iptables chain within table_name
    :returns: A dict of rule_num : rule
    """
    rules = get_iptables_rules_from_chain(table_name, chain_name)
    rules_by_numbers = {rule.rule_num : rule for rule in rules}
    return rules_by_numbers

def add_iptables_rule_to_chain(table_name, chain_name, json_input):
    # the Rule class should do the conversion for us?
    # or maybe some other class?
    with lock_access_iptc:
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

def delete_iptables_rule_from_chain(table_name, chain_name, rule_num, rule_etag):
    with lock_access_iptc:
        table = iptc.Table(table_name.lower())
        table.refresh()
        chains_by_name = {chain.name : chain for chain in table.chains}
        chain = chains_by_name[chain_name.upper()]
        rules = {rule_num : rule for rule_num, rule in enumerate(chain.rules, start=1)}
        rule_to_delete = rules[rule_num]
        rule_object = Rule.build_from_iptables(rule_to_delete, rule_num)
        if rule_object.get_etag() == rule_etag:
            chain.delete_rule(rules[rule_num])
            return True
        # something happened before we got the lock
        return False

class API10:
    """
    This class generates URLs for API version 1.0

    The API allows the following:

    - Enumerating tables
    - Enumerating chains
    - Enumerating rules
    - Adding and removing rules from a chain
    """
    PREFIX = '/api/v1.0'
    TABLE_LIST_URL = '/table'
    TABLE_URL = '/table/%(table_name)s/chain'
    CHAIN_URL = '/table/%(table_name)s/chain/%(chain_name)s/rule'
    RULE_URL = '/table/%(table_name)s/chain/%(chain_name)s/rule/%(rule_num)d'

    @staticmethod
    def get_table_list_url():
        """
        :returns: The URL for the list of tables
        """
        return API10.PREFIX + \
               API10.TABLE_LIST_URL

    @staticmethod
    def get_table_url(table_name):
        """
        :param table_name: Name of the table to request from
        :returns: The URL for the list of chains in a table
        """
        return API10.PREFIX + \
               API10.TABLE_URL % {'table_name' : table_name}

    @staticmethod
    def get_chain_url(table_name, chain_name):
        """
        :param table_name: Name of the table to request from
        :param chain_name: Name of the chain to request from
        :returns: The URL for the list of rules in a chain
        """
        return API10.PREFIX + \
               API10.CHAIN_URL % {'table_name' : table_name,
                                  'chain_name' : chain_name,
                                  }

    @staticmethod
    def get_rule_url(table_name, chain_name, rule_num):
        """
        :param table_name: Name of the table to request from
        :param chain_name: Name of the chain to request from
        :param rule_num: Number of the rule being requested
        :returns: The URL for a given rule
        """
        return API10.PREFIX + \
               API10.RULE_URL % {'table_name' : table_name,
                                  'chain_name' : chain_name,
                                  'rule_num'   : rule_num,
                                  }

class RestfulObject(object):
    """
    Empty superclass with helper REST response functions
    """

    def __init__(self):
        self.response = {}

    def to_rest_response(self):
        """
        :returns: A flask Response containing the data from self.response in JSON format
        """
        return flask.jsonify(self.response)

class IptablesTableList10(RestfulObject):

    def __init__(self):
        super(IptablesTableList10, self).__init__()
        self.populate_response()

    def populate_response(self):
        """
        Populates self.response for REST reply
        """
        self.response['url'] = API10.get_table_list_url()
        tables = []
        for table_name_uppercase in TABLES:
            table_name = table_name_uppercase.lower()
            table_url = API10.get_table_url(table_name)
            table_entry = { 'table_name' : table_name,
                            'url' : table_url,
                          }
            tables.append(table_entry)
        self.response['tables'] = tables

class IptablesTable10(RestfulObject):

    def __init__(self, table_name):
        super(IptablesTable10, self).__init__()
        self.populate_response(table_name)

    def populate_response(self, table_name):
        """
        Populates self.response for REST reply
        """
        self.response['url'] = API10.get_table_url(table_name)
        chains = []
        for chain_name_uppercase in TABLE_CHAINS[table_name.upper()]:
            chain_name = chain_name_uppercase.lower()
            chain_url = API10.get_chain_url(table_name, chain_name)
            chain_entry = { 'table_name' : table_name,
                            'chain_name' : chain_name,
                            'url' : chain_url,
                          }
            chains.append(chain_entry)
        self.response['chains'] = chains

class IptablesChain10(RestfulObject):

    def __init__(self, table_name, chain_name, rules):
        super(IptablesChain10, self).__init__()
        self.populate_response(table_name, chain_name, rules)

    def populate_response(self, table_name, chain_name, rules):
        """
        Populates self.response for REST reply
        """
        self.response['url'] = API10.get_chain_url(table_name, chain_name)
        rule_data = []
        for rule in rules:
            rule_dict = rule.get_dict()
            rule_num = rule_dict['rule_num']
            url = API10.get_rule_url(table_name, chain_name, rule_num)
            rule_entry = { 'table_name' : table_name,
                           'chain_name' : chain_name,
                           'rule_num'   : rule_num,
                           'url'        : url,
                           'data'       : rule_dict
                         }
            rule_data.append(rule_entry)
        self.response['rules'] = rule_data

class IptablesRule10(RestfulObject):

    def __init__(self, table_name, chain_name, rule):
        super(IptablesRule10, self).__init__()
        self.populate_response(table_name, chain_name, rule)

    def populate_response(self, table_name, chain_name, rule):
        """
        Populates self.response for REST reply
        """
        rule_dict = rule.get_dict()
        rule_num = rule_dict['rule_num']
        url = API10.get_rule_url(table_name, chain_name, rule_num)
        rule_entry = { 'table_name' : table_name,
                       'chain_name' : chain_name,
                       'rule_num'   : rule_num,
                       'url'        : url,
                       'data'       : rule_dict
                     }
        self.response = rule_entry

# HTTP Basic Auth code from http://flask.pocoo.org/snippets/8/

def check_auth(username, password):
    """
    This validates a username and password pair

    :param username: Username to authenticate as
    :param password: Password for username
    :returns: True if matching a valid username/password, false otherwise
    """
    return username == 'admin' and password == 'secret'

def authenticate():
    """
    Sends a 401 response to make a user authenticate

    :returns: Flask Response object with code 401
    """
    return flask.Response(
        'You need to authenticate first\n', 401,
        {'WWW-Authenticate' : 'Basic realm="Login required"'})

def requires_auth(f):
    """
    This decorator applies HTTP Basic Auth to a flask method
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = flask.request.authorization
        if not auth or not check_auth(
                auth.username,
                auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/api/v1.0/table', methods=['GET'])
@requires_auth
def show_tables():
    """
    Handler for table enumeration URL
    
    :returns: Flask Response with list of tables in JSON format
    """
    table_list = IptablesTableList10()
    return table_list.to_rest_response()

@app.route('/api/v1.0/table/<table_name>/chain', methods=['GET'])
@requires_auth
def show_chains(table_name):
    """
    Handler for chain enumeration URL
    
    :param table_name: Name of table to look in
    :returns: Flask Response with list of chains in JSON format
    """
    if table_name.upper() not in TABLES:
        flask.abort(400)
    chain_list = IptablesTable10(table_name)
    return chain_list.to_rest_response()

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule', methods=['GET'])
@requires_auth
def show_rules(table_name, chain_name):
    """
    Handler for rule enumeration URL
    
    :param table_name: Name of table to look in
    :param chain_name: Name of chain to look in
    :returns: Flask Response with list of rules in JSON format
    """
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules = get_iptables_rules_from_chain(
                table_name, chain_name)
    rule_list = IptablesChain10(table_name, chain_name, rules)
    return rule_list.to_rest_response()

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule/<int:rule_num>', methods=['GET'])
@requires_auth
def show_rule_by_num(table_name, chain_name, rule_num):
    """
    Handler for rule request URL
    
    :param table_name: Name of table to look in
    :param chain_name: Name of chain to look in
    :param rule_num: Index of rule to return
    :returns: Flask Response with rule in JSON format
    """
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules_by_number = get_iptables_rules_from_chain_by_number(
                table_name, chain_name)
    if rule_num not in rules_by_number.keys():
        flask.abort(400)
    rule = rules_by_number[rule_num]
    rule_data = IptablesRule10(table_name, chain_name, rule)
    response = rule_data.to_rest_response()
    response.headers['ETag'] = rule.get_etag()
    return response

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule/<int:rule_num>', methods=['DELETE'])
@requires_auth
def delete_rule_by_num(table_name, chain_name, rule_num):
    """
    Handler for rule delete URL

    This requires the ETag field to be set to the 
    ETag returned by the rule on a previous request.
    This prevents clients from accidentally deleting
    the wrong rule.

    This will throw a 403 if the ETag is not set, 412
    if the ETag is not correct or rule otherwise
    couldn't be deleted, or 204 if the deletion
    was successful.
    
    :param table_name: Name of table to look in
    :param chain_name: Name of chain to look in
    :param rule_num: Index of rule to delete
    :returns: Flask Response depending on success
    """
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    rules_by_number = get_iptables_rules_from_chain_by_number(
                table_name, chain_name)
    if rule_num not in rules_by_number.keys():
        flask.abort(400)
    rule = rules_by_number[rule_num]
    rule_dict = rule.get_dict()
    #rule_data = IptablesRule10(table_name, chain_name, rule)
    rule_etag = rule.get_etag()
    if 'ETag' not in flask.request.headers:
        flask.abort(403)
    if flask.request.headers.get('ETag') != rule_etag:
        flask.abort(412)
    # this is a major race condition candidate, should take ETag and compare just before alter
    # probably want some sort of locking at a minimum
    success = delete_iptables_rule_from_chain(table_name, chain_name, rule_num, rule_etag)
    if success:
        response = flask.make_response('', 204)
    else:
        flask.abort(412)
    return response

@app.route('/api/v1.0/table/<table_name>/chain/<chain_name>/rule', methods=['POST'])
@requires_auth
def add_rule(table_name, chain_name):
    """
    Handler for rule add URL

    This requires the client to submit the specifications of
    the rule in JSON format
    
    :param table_name: Name of table to look in
    :param chain_name: Name of chain to look in
    :returns: Flask Response with new rule in JSON format
    """
    if table_name.upper() not in TABLES:
        flask.abort(400)
    if chain_name.upper() not in TABLE_CHAINS[table_name.upper()]:
        flask.abort(400)
    # get the chain they want
    if not flask.request.json:
        flask.abort(400)

    add_iptables_rule_to_chain(table_name, chain_name, flask.request.json)
    # when inserting at front, rule_num will be 1
    rule_num = 1
    return show_rule_by_num(table_name, chain_name, rule_num)

def main():
    app.debug = True
    app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
