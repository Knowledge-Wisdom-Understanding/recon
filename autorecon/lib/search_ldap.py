#!/usr/bin/env python3

import ldap
import json
import pprint
import sys


class enumLdap:
    def __init__(self, target):
        self.target = target
        self.l = ldap.initialize(f'ldap://{self.target}')
        self.cache = {}

    def get_base_context(self):
        if "base_domain" in self.cache:
            return self.cache['base']
        else:
            top_level = self.l.search_s('', ldap.SCOPE_BASE, 'objectClass=top')
            naming_context = top_level[0][1]['namingContexts'][0].decode('utf-8')
            print(f"Naming Context: {naming_context}")
            self.cache['base'] = naming_context
            return naming_context

    def get_domain(self):
        base = self.get_base_context()
        domain = base.replace('DC=', '').replace(',', '.')
        return domain

    def get_all_users(self):
        if "users" in self.cache:
            return self.cache['users']
        else:
            all_users = self.l.search_s(self.get_base_context(), ldap.SCOPE_SUBTREE,
                                        filterstr='(&(sAMAccountName=*)(objectClass=user))',
                                        attrlist=['sAMAccountName', 'pwdLastSet', 'mail', 'lastLogon'])
            self.cache['users'] = all_users
            return all_users
