control 'SV-994' do
  title 'The snmpd.conf file must have mode 0600 or less permissive.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Check the mode of the SNMP daemon configuration file.

Locate the SNMP daemon configuration file. Consult vendor documentation to verify the name and location of the file.
Procedure:
# find / -name snmpd.conf

Check the mode of the SNMP daemon configuration file.
Procedure:
# ls -lL <snmpd.conf>

If the snmpd.conf file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the SNMP daemon configuration file to 0600. 

Procedure:
# chmod 0600 <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-817r2_chk'
  tag severity: 'medium'
  tag gid: 'V-994'
  tag rid: 'SV-994r2_rule'
  tag stig_id: 'GEN005320'
  tag gtitle: 'GEN005320'
  tag fix_id: 'F-1148r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
