control 'SV-227878' do
  title 'The snmpd.conf file must have mode 0600 or less permissive.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Check the mode of the SNMP daemon configuration files.
Procedure:
# ls -lL /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /var/sma_snmp/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf

If any of the snmpd.conf files have a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the SNMP daemon configuration file to 0600. 

Procedure:
# chmod 0600 <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30040r490030_chk'
  tag severity: 'medium'
  tag gid: 'V-227878'
  tag rid: 'SV-227878r603266_rule'
  tag stig_id: 'GEN005320'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30028r490031_fix'
  tag 'documentable'
  tag legacy: ['V-994', 'SV-40262']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
