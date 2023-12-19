control 'SV-218582' do
  title 'The snmpd.conf file must have mode 0600 or less permissive.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Check the mode of the SNMP daemon configuration file.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf

# ls -lL <snmpd.conf file>

If the snmpd.conf file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the SNMP daemon configuration file to 0600. 

Procedure:
# chmod 0600 <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20057r555944_chk'
  tag severity: 'medium'
  tag gid: 'V-218582'
  tag rid: 'SV-218582r603259_rule'
  tag stig_id: 'GEN005320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20055r555945_fix'
  tag 'documentable'
  tag legacy: ['V-994', 'SV-63425']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
