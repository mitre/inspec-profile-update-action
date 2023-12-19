control 'SV-86173' do
  title 'The CA API Gateway must generate an alert that will then be sent to the ISSO, ISSM, and other designated personnel (deemed appropriate by the local organization) when the unauthorized installation of software is detected.'
  desc 'Unauthorized software not only increases risk by increasing the number of potential vulnerabilities, it also can contain malicious code. Sending an alert (in real time) when unauthorized software is detected allows designated personnel to take action on the installation of unauthorized software. Note that while the device must generate the alert, the notification may be done by a management server.'
  desc 'check', %q(Verify "/usr/local/bin/alerter" script exists and is executable. 

Verify crontab runs "/usr/local/bin/alerter" every minute by checking cron's logfile /var/log/cron.

If the "/usr/local/bin/alerter" script does not exist, this is a finding. 

If the "/usr/local/bin/alerter" script does not run every minute as a cron job, this is a finding. 

An example follows. The SNMP destination host and username/password are configured by editing the shell variables near the beginning of the script. SNMPUSER should be set to the username recognized by the SNMP Management Station. SNMPENGINEID should be set to the SNMPv3 EngineID the Management Station uses for this application. SNMPHOST should be set to the hostname of the SNMP Management Station. 

This authentication configuration is placed in "/etc/snmp/snmp.conf":
-----------------------------------
defSecurityLevel authPriv
defAuthType SHA
defPrivType AES
defAuthPassphrase {password123}
defPrivPassphrase {password123}
-----------------------------------

This snmp alerter script is placed in "/usr/local/bin/alerter script":
--------
#!/bin/bash

#
# This script implements watching for changes in a system that may indicate unauthorized
# changes have been made to the system
#
# It is designed to be run as "alerter -w" to capture the current configuration and
# then to be run out of cron on a regular basis as "alerter -c" which then compares the
# current configuration to the previously captured configuration. If the configuration
# has changed an SNMP TRAP is sent using the SNMPBASECMD variable as the base snmptrap command.
# SNMPBASECMD will have to be configured appropriately depending on the exact SNMPv3 security
# implemented on the SNMP Management Server.
#
# The script uses /var/run/alerter as a base directory to capture filesystem timestamps and
# the installed RPM software list.

SNMPUSER=myuser
SNMPENGINEID=0x0102030405
SNMPHOST=rsbfreebsd.ca.com

SNMPENTNUM="1.3.6.1.4.1.17304"
SNMPNOTIF=".7.3.128"
SNMPBASECMD="snmptrap -v 3 -n \"\" -u ${SNMPUSER} -e ${SNMPENGINEID} ${SNMPHOST} 0 ${SNMPENTNUM}.7.3.128.0 ${SNMPENTNUM}.7.3.129.0 s"

ALERTER_ROOT=/var/run/alerter

ACCOUNTFILES=("/etc/passwd" "/etc/shadow" "/etc/group")

TSFILE=timestamps
RPMFILE=rpmlist

function usage {
  echo "$0 [-w | -c]"
  echo "   -w - Write data"
  echo "   -c - Compare current to data"
  echo "   (at least one must be selected)"
  echo
}

function writeTsSummary {
  for file in ${ACCOUNTFILES[*]} 
  do
    ts=$(stat -c '%Y' $file)
    echo $file $ts >> $ALERTER_ROOT/$TSFILE
  done
}

function writeRpmSummary {
  rpm -qa >> $ALERTER_ROOT/$RPMFILE
}

function writeSummaries {

  if [ ! -d $ALERTER_ROOT ]
  then
    mkdir $ALERTER_ROOT
  fi

  rm -f $ALERTER_ROOT/$TSFILE $ALERTER_ROOT/$RPMFILE

  writeTsSummary
  writeRpmSummary
})
  desc 'fix', %q(Install and configure (setup SNMP trap dest/authentication) alerter script in "/usr/local/bin/alerter". 

Run "/usr/local/bin/alerter -w" to write initial config to filesystem. 

Configure cron to run "/usr/local/bin/alerter -c" every minute.

An example follows. The SNMP destination host and username/password are configured by editing the shell variables near the beginning of the script. SNMPUSER should be set to the username recognized by the SNMP Management Station. SNMPENGINEID should be set to the SNMPv3 EngineID the Management Station uses for this application. SNMPHOST should be set to the hostname of the SNMP Management Station. 

This authentication configuration is placed in "/etc/snmp/snmp.conf":
-----------------------------------
defSecurityLevel authPriv
defAuthType SHA
defPrivType AES
defAuthPassphrase {password123}
defPrivPassphrase {password123}
-----------------------------------

This snmp alerter script is placed in "/usr/local/bin/alerter script":
--------
#!/bin/bash

#
# This script implements watching for changes in a system that may indicate unauthorized
# changes have been made to the system
#
# It is designed to be run as "alerter -w" to capture the current configuration and
# then to be run out of cron on a regular basis as "alerter -c" which then compares the
# current configuration to the previously captured configuration. If the configuration
# has changed an SNMP TRAP is sent using the SNMPBASECMD variable as the base snmptrap command.
# SNMPBASECMD will have to be configured appropriately depending on the exact SNMPv3 security
# implemented on the SNMP Management Server.
#
# The script uses /var/run/alerter as a base directory to capture filesystem timestamps and
# the installed RPM software list.

SNMPUSER=myuser
SNMPENGINEID=0x0102030405
SNMPHOST=rsbfreebsd.ca.com

SNMPENTNUM="1.3.6.1.4.1.17304"
SNMPNOTIF=".7.3.128"
SNMPBASECMD="snmptrap -v 3 -n \"\"  -u ${SNMPUSER} -e ${SNMPENGINEID} ${SNMPHOST} 0 ${SNMPENTNUM}.7.3.128.0 ${SNMPENTNUM}.7.3.129.0 s"

ALERTER_ROOT=/var/run/alerter

ACCOUNTFILES=("/etc/passwd" "/etc/shadow" "/etc/group")

TSFILE=timestamps
RPMFILE=rpmlist

function usage {
  echo "$0 [-w | -c]"
  echo "   -w - Write data"
  echo "   -c - Compare current to data"
  echo "   (at least one must be selected)"
  echo
}

function writeTsSummary {
  for file in ${ACCOUNTFILES[*]} 
  do
    ts=$(stat -c '%Y' $file)
    echo $file $ts >> $ALERTER_ROOT/$TSFILE
  done
}

function writeRpmSummary {
  rpm -qa >> $ALERTER_ROOT/$RPMFILE
}

function writeSummaries {

  if [ ! -d $ALERTER_ROOT ]
  then
    mkdir $ALERTER_ROOT
  fi

  rm -f $ALERTER_ROOT/$TSFILE $ALERTER_ROOT/$RPMFILE

  writeTsSummary
  writeRpmSummary
})
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71549'
  tag rid: 'SV-86173r1_rule'
  tag stig_id: 'CAGW-DM-000250'
  tag gtitle: 'SRG-APP-000377-NDM-000301'
  tag fix_id: 'F-77869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
