#!/usr/bin/env python3

from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples import logger
from impacket.nt_errors import STATUS_MORE_ENTRIES
import logging
import json
from datetime import datetime
from tabulate import tabulate
from sty import fg


class ListUsersException(Exception):
    pass


class SamrDisplayInfo:
    def __init__(self, target, domain, port=445):
        self.target = target
        self.domain = domain
        self.__port = port

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def dump(self, remoteName, remoteHost):
        """Dumps the list of users and shares registered present at
        remoteName. remoteName is a valid host name or IP address.
        """

        entries = []

        logging.info('Retrieving endpoint list from %s' % remoteName)

        stringbinding = r'ncacn_np:%s[\pipe\samr]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials('', '', self.domain, '',
                                         '', None)
        rpctransport.set_kerberos(False, self.target)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception as e:
            logging.critical(str(e))

        table_headers = ["Username", "FullName", "UserComment", "PrimaryGroupId", "BasPasswordCount", "LogonCount",
                         "PasswordLastSet", "PasswordDoesNotExpire", "AccoutIsDisabled", "ScriptPath", "AdminComment"]
        data_entries = []
        password_entries = []
        for entry in entries:
            (username, uid, user) = entry
            pwdLastSet = (user['PasswordLastSet']['HighPart'] << 32) + user['PasswordLastSet']['LowPart']
            if pwdLastSet == 0:
                pwdLastSet = '<never>'
            else:
                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(pwdLastSet)))

            if user['UserAccountControl'] & samr.USER_DONT_EXPIRE_PASSWORD:
                dontExpire = 'True'
            else:
                dontExpire = 'False'

            if user['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED:
                accountDisabled = 'True'
            else:
                accountDisabled = 'False'
            if user['AdminComment']:
                password_entries.append({'username': username, 'AdminComment': user['AdminComment']})

            base = "%s (%d)" % (username, uid)
            data_entries.append([base, user['FullName'], user['UserComment'], user['PrimaryGroupId'], user['BadPasswordCount'],
                                 user['LogonCount'], pwdLastSet, dontExpire, accountDisabled, user['ScriptPath'], user['AdminComment']])
        print(tabulate(data_entries, headers=table_headers))
        if entries:
            num = len(entries)
            if 1 == num:
                logging.info('Received one entry.')
            else:
                logging.info('Received %d entries.' % num)
        else:
            logging.info('No entries received.')
        # print(json.dumps(password_entries, indent=2))
        return password_entries

    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            print('Found domain(s):')
            for domain in domains:
                print(" . %s" % domain['Name'])

            logging.info("Looking up users in domain %s" % domains[0]['Name'])

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

            resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    print("Found user: %s, uid = %d" % (user['Name'], user['RelativeId']))
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

        except ListUsersException as e:
            logging.critical("Error listing users: %s" % e)

        dce.disconnect()

        return entries
