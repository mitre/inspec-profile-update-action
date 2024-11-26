control 'SV-38785' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If there are excessive file permissions for the cron.deny file, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', '#aclget /var/adm/cron/cron.deny

Verify if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cron.deny file and disable extended permissions.

#acledit /var/adm/cron/cron.deny'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22389'
  tag rid: 'SV-38785r1_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'GEN003210'
  tag fix_id: 'F-32476r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
