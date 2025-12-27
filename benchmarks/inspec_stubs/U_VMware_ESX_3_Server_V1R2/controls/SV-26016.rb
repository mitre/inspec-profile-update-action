control 'SV-26016' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', 'Determine if system audit files have an extended ACL.  If any do, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the system audit file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29200r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22369'
  tag rid: 'SV-26016r1_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'GEN002710'
  tag fix_id: 'F-26222r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
