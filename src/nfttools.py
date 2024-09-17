#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# License for this file: MIT

import ast
import json
import nftables


class NftTools():

    def __init__(self, tablename='validator'):
        """Initializes the libnftables interface and prepares a chain for later use"""
        self.tablename = tablename
        self._nft = nftables.Nftables()
        # Settings
        self._nft.set_json_output(True)
        self._nft.set_stateless_output(True)
        self._nft.set_service_output(False)
        self._nft.set_reversedns_output(False)
        self._nft.set_numeric_proto_output(True)
        self._nft.set_echo_output(True)
        # Add table and chain (both is idempotent)
        basics_json = {'nftables': [
            { 'add': { 'table': {
                'family': 'inet',
                'name': tablename
            }}},
            { 'add': { 'chain': {
                'family': 'inet',
                'table': tablename,
                'name': 'validator'
            }}},
#            { 'flush': { 'table': { # flushes all chains but does not remove sets
#                'family': 'inet',
#                'name': tablename
#            }}},
        ]}
        self.run_cmd_json(basics_json)

    def run_cmd_json(self, json_str, raise_exception=True):
        """Sends the given JSON commands to nftables"""
        self._nft.json_validate(json_str)
        rc, out, err = self._nft.json_cmd(json_str)
        if (rc != 0) or (len(err) != 0):
            if raise_exception:
                raise RuntimeError(f'nftables call [{json_str}] failed unexpectedly [{err}]')
            return rc, err  # return error explanation
        return rc, out

    def get_ruleset_json(self):
        """Returns the current ruleset of our table in JSON notation"""
        rc, out, err = self._nft.cmd(f'list table inet {self.tablename}')
        if (rc != 0) or (len(err) != 0):
            # Return error explanation
            return rc, err
        data = json.loads(out)
        return 0, data
        
    def get_sets(self, table_json):
        """Returns a dictionary with all nftables sets (based on the given JSON representation of a table)"""
        result = dict()
        data = table_json.get('nftables')
        for item in data:
            if 'set' in item:
                item_data = item.get('set')
                # Example content: item_data = {'family': 'inet', 'name': 'mysource2', 'table': 'validator', 'type': 'ipv4_addr', 'handle': 2}
                result[item_data.get('name')] = item_data
        return result
        
    def ensure_sets_internal(self, sets_current, sets_target, ipv6=False, delete_surplus=True):
        """Ensures that exactly the sets (names in provided list) exist with the correct family/type"""
        type_target = 'ipv6_addr' if ipv6 else 'ipv4_addr'
        # Identify what needs to be done
        list_del = []
        list_add = []
        for name in sets_target:
            if name in sets_current:
                if sets_current[name]['type'] != type_target:
                    list_del.append(name) # delete set of wrong type
                    list_add.append(name) # add with correct type
            else:
                list_add.append(name) # add since it is not existing
        if delete_surplus:
            for name in (set(sets_current) - set(sets_target)):
                list_del.append(name)
        # Create list of nftables actions to run
        data = []
        for name in list_del:
            data.append(
                { 'delete': { 'set': { # would fail if set does not exist
                    'table': self.tablename,
                    'family': 'inet',
                    'name': name,
                }}}
            )
        for name in list_add:
            data.append(
                { 'add': { 'set': {
                    'family': 'inet',
                    'table': self.tablename,
                    'name': name,
                    'type': type_target
                }}}
            )
        # Run command if something needs to be changed
        if len(data):
            data = {'nftables': data}
            rc, out = self.run_cmd_json(data)
            return (rc == 0)
        return True

    def ensure_sets(self, sets_target, ipv6=False, delete_surplus=True):
        """Ensures that exactly the sets (names in provided list) exist with the correct family/type"""
        rc, result = self.get_ruleset_json()
        if rc == 0:
            sets = self.get_sets(result)
            self.ensure_sets_internal(sets, sets_target, ipv6=ipv6, delete_surplus=delete_surplus)

    def check_rule(self, rule):
        """Checks the validity of the given rule by temporarily adding it and returns the JSON representation on success"""
        rc, out, err = self._nft.cmd(f'add rule inet {self.tablename} validator ' + rule)
        if (rc != 0) or (len(err) != 0):
            # Return error explanation
            return rc, err
        rc, _, err = self._nft.cmd(f'flush chain inet {self.tablename} validator')
        if (rc != 0) or (len(err) != 0):
            raise RuntimeError(f'nftables call failed unexpectedly [{err}]')
        # Since we enabled echo, output contains the rule's JSON representation
        return 0, out

    def check_rule_with_sets(self, rule):
        """Checks the validity of the given rule (may contain references to sets) by temporarily adding it and returns the JSON representation on success"""
        parts = rule.split(' ')
        # Example: parts = ['ip', 'daddr', '1.2.3.4/24', 'tcp', 'dport', '8428', 'ip', 'saddr', '@mysource', 'tcp', 'sport', '65000', 'accept']
        # Note: Something like "{@mysource1, @mysource2}" is not supported by nftables - nevertheless, we make sure that no sets with special characters like brackets are created
        # Example: parts = ['ip', 'daddr', '1.2.3.4/24', 'tcp', 'dport', '8428', 'ip', 'saddr', '{@mysource1,', '@mysource2}', 'tcp', 'sport', '65000', 'accept']
        sets = parts
        sets = [ name[1:] if name.startswith('{') else name for name in sets ]  # remove bracket from beginning
        sets = [ name[:-1] if name.endswith('}') else name for name in sets ]  # remove bracket from end
        sets = [ name[:-1] if name.endswith(',') else name for name in sets ]  # remove comma from end
        sets = [ name[1:] for name in sets if name.startswith('@') ]  # select items with @ at beginning and remove the @
        # Example: sets = ['mysource']
        if len(sets):  # nothing to do if not sets referenced in rule
            ipv6 = 'ip6' in parts
            self.ensure_sets(sets, ipv6=ipv6, delete_surplus=True)
        return self.check_rule(rule)

    def convert_rule_str2json(self, rule):
        """Converts the given rule to JSON representation (if valid)"""
        rc, result = self.check_rule_with_sets(rule)
        if rc == 0:
            # Convert output to nested Python dict/list
            result = json.loads(result)
            # Strip unneeded info
            result = result.get('nftables')[0].get('add').get('rule')
            result = result.get('expr')
            print('convert_rule_str2json yields:', result)
            # Return JSON representation of the rule
            return 0, result
        else:
            # Return error info (non-zero return code)
            return rc, result
            
    @staticmethod
    def convert_rule_json2dict(json_expr):
        """Parses a simple rule provided in JSON into a dictionary representation"""
        
        def values2str(data):
            """Recursively convert the nested expression into a human-readable string representation"""
            if not isinstance(data, dict):
                return str(data)
            if 'set' in data:
                # Example: {'set': [123, {'range': [8428, 8429]}]}
                items = data.get('set')
                items = [ values2str(item) for item in items ]
                return ', '.join(items)
            elif 'range' in data:
                # Example: {'range': [8428, 8429]}
                items = data.get('range')
                if len(items) != 2:
                    return None
                return str(items[0]) + '-' + str(items[1])
            elif 'prefix' in data:
                # Example: {'prefix': {'addr': '192.168.0.0', 'len': 24}}
                items = data.get('prefix')
                return items.get('addr') + '/' + str(items.get('len'))
            else:
                return None
            return data
        
        assert isinstance(json_expr, list)
        result = dict()
        result['ipv6'] = None
        for item in json_expr:
            if 'accept' in item:
                result['action'] = 'accept'
            elif 'drop' in item:
                result['action'] = 'drop'
            elif 'reject' in item:
                result['action'] = 'reject'
            elif 'match' in item:
                value = item.get('match')
                if value.get('op') == '==':
                    right = value.get('right')
                    right = values2str(right)
                    if right:
                        left = value.get('left')
                        payload = left.get('payload')
                        if payload is not None:
                            protocol = payload.get('protocol')
                            field = payload.get('field')
                            if ((protocol == 'ip') or (protocol == 'ip6')) and ((field == 'saddr') or (field == 'daddr')):
                                result[field] = right
                                result['ipv6'] = (protocol == 'ip6')
                            elif ((protocol == 'ip') and (field == 'protocol')) or ((protocol == 'ip6') and (field == 'nexthdr')):
                                if right == '1':
                                    result['protocol'] = 'icmp'
                                elif right == '6':
                                    result['protocol'] = 'tcp'
                                elif right == '17':
                                    result['protocol'] = 'udp'
                                else:
                                    result['error'] = f'Unsupported protocol in match expression, value {value}'
                                result['ipv6'] = (protocol == 'ip6')
                            elif ((protocol == 'tcp') or (protocol == 'udp')) and ((field == 'sport') or (field == 'dport')):
                                result['protocol'] = protocol
                                s = values2str(right)
                                if s:
                                    result[field] = s
                                else:
                                    result['error'] = f'Unsupported expression on the right side of the {field} match expression, value {value}'
                            else:
                                result['error'] = f'Unsupported protocol/field in match expression, value {value}'
                        else:
                            result['error'] = f'No payload given in left side of match expression, value {value}'
                    else:
                        result['error'] = f'Unsupported expression on the right side of the match expression, value {value}'
                else:
                    result['error'] = f'Unsupported operator in match expression, value {value}'                
            else:
                result['error'] = f'Unsupported key {item} in JSON expression'
        # Example: {'ipv6': False, 'daddr': '1.2.3.0/24', 'protocol': 'tcp', 'dport': '123, 8428-8429', 'saddr': '10.28.1.0/24', 'sport': '65000', 'action': 'accept'}
        return result

    @staticmethod
    def convert_rule_jsonstr2dict(json_str):
        """Parses a simple rule provided as a JSON string into a dictionary representation"""
        assert isinstance(json_str, str)
        data = ast.literal_eval(json_str)  # no json.loads to support single quotes
        return NftTools.convert_rule_json2dict(data)

    @staticmethod
    def convert_rule_dict2str(data):
        """Converts a simple rule provided in dictionary representation into a rule string"""

        def expand_str(s):
            """Expands the provided comma-separated list into properly encoded set"""
            s_parts = s.split(',')
            # Strip superfluous spaces
            s_parts = [ part.strip() for part in s_parts ]
            s = ', '.join(s_parts)
            # Return correclty formatted string
            if len(s_parts) > 1:
                return '{' + s + '}'
            else:
                return s

        result = []
        ipv6 = data.get('ipv6')
        ip_version = 'ip6' if ipv6 else 'ip'
        if data.get('daddr'):
            result.append(f'{ip_version} daddr {expand_str(data.get("daddr"))}')
        if data.get('protocol') and (ipv6 is not None) and not data.get('dport') and not data.get('sport'):
            result.append(f'{ip_version} {"nexthdr" if ipv6 else "protocol"} {expand_str(data.get("protocol"))}')
        if data.get('dport'):
            result.append(f'{data.get("protocol")} dport {expand_str(data.get("dport"))}')
        if data.get('saddr'):
            result.append(f'{ip_version} saddr {expand_str(data.get("saddr"))}')
        if data.get('sport'):
            result.append(f'{data.get("protocol")} sport {expand_str(data.get("sport"))}')
        if data.get('action'):
            result.append(data.get('action'))
        return ' '.join(result)


if __name__ == '__main__':
    nft = NftTools()
    rc, result = nft.convert_rule_str2json('tcp dport 8428 ip saddr 10.28.1.97 accept')
    print(rc, result, NftTools.convert_rule_json2dict(result))
    # Comments are not included in JSON output
    rc, result = nft.convert_rule_str2json('tcp dport 8428 ip saddr 10.28.1.97 accept comment "Hallo"')
    print(rc, result, NftTools.convert_rule_json2dict(result))
    # Many matches
    rc, result = nft.convert_rule_str2json('ip daddr 1.2.3.4/24 tcp dport { 8428-8429, 123 } ip saddr 10.28.1.0/24 tcp sport 65000 accept')
    print(rc, result, NftTools.convert_rule_json2dict(result))
    # Set
    rc, result = nft.convert_rule_str2json('ip daddr 1.2.3.4/24 tcp dport 8428 ip saddr @mysource tcp sport 65000 accept')
    print(rc, result, NftTools.convert_rule_json2dict(result))
    # Protocols are given as numeric values in JSON output
    rc, result = nft.convert_rule_str2json('ip protocol tcp drop') # 6
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('ip6 nexthdr tcp drop') # 6
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('ip protocol udp drop') # 17
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('ip6 nexthdr udp drop') # 17
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('ip protocol icmp drop') # 1
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('ip6 nexthdr icmp drop') # 1
    print(rc, result, NftTools.convert_rule_json2dict(result))
    rc, result = nft.convert_rule_str2json('reject')
    print(rc, result, NftTools.convert_rule_json2dict(result))
    #nft.ensure_sets(['b'], False)
    print(NftTools.convert_rule_dict2str({'ipv6': False, 'daddr': '1.2.3.0/24', 'protocol': 'tcp', 'dport': '123, 8428-8429', 'saddr': '10.28.1.0/24', 'sport': '65000', 'action': 'accept'}))
