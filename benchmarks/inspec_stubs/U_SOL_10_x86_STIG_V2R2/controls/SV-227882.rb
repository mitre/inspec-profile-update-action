control 'SV-227882' do
  title 'The snmpd.conf file must be group-owned by root, sys, or bin.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not group-owned by a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Check the group ownership of the SNMP configuration files.

Procedure:
# ls -lL /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf

If the files are not group-owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group ownership of the SNMP configuration file.

Procedure:
# chgrp root /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30044r490042_chk'
  tag severity: 'medium'
  tag gid: 'V-227882'
  tag rid: 'SV-227882r603266_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30032r490043_fix'
  tag 'documentable'
  tag legacy: ['V-22451', 'SV-26733']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
