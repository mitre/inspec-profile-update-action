control 'SV-26039' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If there are excessive file permissions for the cron.deny file, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Determine if the cron.deny file has an extended ACL.  If so, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cron.deny file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29220r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22389'
  tag rid: 'SV-26039r1_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'GEN003210'
  tag fix_id: 'F-26241r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
