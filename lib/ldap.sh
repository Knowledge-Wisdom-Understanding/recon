#!/usr/bin/env bash

rhost=$1
NICE='\e[1;32;92m[+]\e[0m'

ldap_enum() {
    echo -e "${NICE} ldapsearch -x -h $rhost -s base namingcontexts"
    ldapsearch -x -h $rhost -s base namingcontexts | tee $rhost-Report/ldap/ldap-namingcontext.log
    dcList=$(sed -n -e 's/^.*namingContexts: //p' $rhost-Report/ldap/ldap-namingcontext.log)
    echo -e "${NICE} ldapsearch -x -h $rhost -s base -b $dcList"
    ldapsearch -x -h $rhost -s base -b $dcList | tee $rhost-Report/ldap/ldap-base.log
    echo -e "${NICE} ldapsearch -x -h $rhost -s sub -b $dcList"
    ldapsearch -x -h $rhost -s sub -b $dcList | tee $rhost-Report/ldap/ldap-sub.log
    ldapUserNames=$(sed -n -e 's/^.*uid=//p' $rhost-Report/nmap/ldap.nmap | cut -d ',' -f 1)
    sambaNTPassword=$(sed -n -e 's/^.*sambaNTPassword: //p' $rhost-Report/nmap/ldap.nmap)
    # ldapUserPasswords=$(sed -n -e 's/^.*userPassword: //p' $rhost-Report/nmap/ldap.nmap)

    sortUsers() {
        for user in $ldapUserNames; do
            if [[ -n $sambaNTPassword ]]; then
                if (($(grep -c . <<<"$sambaNTPassword") > 1)); then
                    for hash in $sambaNTPassword; do
                        echo -e "${NICE} smbmap -u $user -p "$hash:$hash" -H $rhost -R"
                        smbmap -u $user -p "$hash:$hash" -H $rhost -R
                    done
                else
                    echo -e "${NICE} smbmap -u $user -p "$sambaNTPassword:$sambaNTPassword" -H $rhost -R"
                    smbmap -u $user -p "$sambaNTPassword:$sambaNTPassword" -H $rhost -R
                fi
            fi
        done
    }
    sortUsers
}
ldap_enum
