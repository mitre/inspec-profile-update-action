control 'SV-37703' do
  title 'The snmpd.conf file must be owned by root.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not owned by root, it may be subject to access and modification from unauthorized users.'
  desc 'fix', 'Change the owner of the snmpd.conf file to root.

Procedure:
# chown root <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12019'
  tag rid: 'SV-37703r1_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'GEN005360'
  tag fix_id: 'F-32028r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
