control 'SV-26044' do
  title 'The at.deny file must not have an extended ACL.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected. Unauthorized modification of the at.deny file could result in Denial-of-Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', "Determine if the at.deny file has an extended ACL.
# ls -l at.deny
If the file's permissions contain a '+', the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the at.deny file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29228r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22393'
  tag rid: 'SV-26044r1_rule'
  tag stig_id: 'GEN003255'
  tag gtitle: 'GEN003255'
  tag fix_id: 'F-26249r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
