control 'SV-226970' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy  provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use the information to launch attacks against the system.'
  desc 'check', "Verify the SNMP daemon is not configured to use the v1 or v2c security models.
# egrep '(v1|v2c|community|com2sec)' /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf | grep -v '^#'
If any configuration is found, this is a finding."
  desc 'fix', 'Edit non-compliant snmpd.conf files and remove references to the v1, v2c, community, or com2sec.  Restart the SNMP service.
# svcadm restart svc:/application/management/sma:default'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29132r485240_chk'
  tag severity: 'medium'
  tag gid: 'V-226970'
  tag rid: 'SV-226970r603265_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29120r485241_fix'
  tag 'documentable'
  tag legacy: ['V-22447', 'SV-26715']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
