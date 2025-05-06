control 'SV-26738' do
  title 'The snmpd.conf file must not have an extended ACL.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Check the permissions of the SNMP configuration file.
# ls -lL /etc/SnmpAgent.d/snmpd.conf

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /etc/SnmpAgent.d/snmpd.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22452'
  tag rid: 'SV-26738r1_rule'
  tag stig_id: 'GEN005375'
  tag gtitle: 'GEN005375'
  tag fix_id: 'F-31983r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
