control 'SV-37696' do
  title 'The snmpd.conf file must have mode 0600 or less permissive.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'fix', 'Change the mode of the SNMP daemon configuration file to 0600. 

Procedure:
# chmod 0600 <snmpd.conf>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-994'
  tag rid: 'SV-37696r1_rule'
  tag stig_id: 'GEN005320'
  tag gtitle: 'GEN005320'
  tag fix_id: 'F-31997r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
