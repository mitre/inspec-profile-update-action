control 'SV-38816' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use the information to launch attacks against the system.'
  desc 'check', "Determine if the system's SNMP service only uses SNMPv3 or its successors. Consult vendor documentation to determine if earlier versions of SNMP are supported and what configuration is necessary to enable or disable the protocols.  Snmpd version 1 was the only version available in AIX versions prior to AIX 5.2.

#which snmpd
#ls -l <path to snmpd>
If the results are not /usr/sbin/snmpdv3e or /usr/sbin/snpdv3ne this is an earlier version of the protocol used by the service, this is a finding."
  desc 'fix', "Configure the system's SNMP service to only use SNMPv3 with encryption or its successors.   The SNMP version supporting encryption is an installable fileset on the expansion cd as fileset 'snmp.crypto'.

Enable snmpv3 with encryption.

# snmpv3_ssw -e"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22447'
  tag rid: 'SV-38816r1_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'GEN005305'
  tag fix_id: 'F-32325r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
