control 'SV-37917' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'fix', 'Remove the extended ACL from the system audit file(s).'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22369'
  tag rid: 'SV-37917r1_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'GEN002710'
  tag fix_id: 'F-26222r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
