control 'SV-38786' do
  title 'The at.allow file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Unauthorized modification of the at.allow file could result in Denial of Service to authorized at users and the granting of the ability to run at jobs to unauthorized users.'
  desc 'check', '#aclget /var/adm/cron/at.allow
Verify if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the at.allow file and disable extended permissions.

#acledit /var/adm/cron/at.allow'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22390'
  tag rid: 'SV-38786r1_rule'
  tag stig_id: 'GEN003245'
  tag gtitle: 'GEN003245'
  tag fix_id: 'F-32477r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
