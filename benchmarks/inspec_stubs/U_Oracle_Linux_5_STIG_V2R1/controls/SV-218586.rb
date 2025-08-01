control 'SV-218586' do
  title 'The snmpd.conf file must be group-owned by root, bin, sys, or system.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not group-owned by a system group, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Check the group ownership of the SNMP configuration file.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# ls -lL <snmpd.conf>

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the SNMP configuration file.

Procedure:
# chgrp root <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20061r555956_chk'
  tag severity: 'medium'
  tag gid: 'V-218586'
  tag rid: 'SV-218586r603259_rule'
  tag stig_id: 'GEN005365'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20059r555957_fix'
  tag 'documentable'
  tag legacy: ['V-22451', 'SV-63461']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
