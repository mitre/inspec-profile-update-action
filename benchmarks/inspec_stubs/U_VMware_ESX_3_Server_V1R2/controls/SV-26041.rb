control 'SV-26041' do
  title 'The at.allow file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Unauthorized modification of the at.allow file could result in Denial-of-Service to authorized "at" users and the granting of the ability to run "at" jobs to unauthorized users.'
  desc 'check', 'Determine if the at.allow file has an extended ACL.  If it does, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the at.allow file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22390'
  tag rid: 'SV-26041r1_rule'
  tag stig_id: 'GEN003245'
  tag gtitle: 'GEN003245'
  tag fix_id: 'F-26242r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
