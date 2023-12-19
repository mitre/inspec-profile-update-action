control 'SV-35176' do
  title 'The snmpd.conf file must have mode 0600 or less permissive.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'fix', 'Change the mode of the SNMP daemon configuration file to 0600. 
# chmod 0600 /etc/SnmpAgent.d/snmpd.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-994'
  tag rid: 'SV-35176r1_rule'
  tag stig_id: 'GEN005320'
  tag gtitle: 'GEN005320'
  tag fix_id: 'F-31978r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
