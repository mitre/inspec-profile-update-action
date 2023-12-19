control 'SV-38790' do
  title 'The at directory must not have an extended ACL.'
  desc 'If the at directory has an extended ACL, unauthorized users could be allowed to view or to edit files containing sensitive information within the at directory. Unauthorized modifications could result in Denial of Service to authorized at jobs.'
  desc 'check', 'Check the permissions of the file.
#aclget /var/spool/cron/atjobs 
Verify if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the at directory and disable extended permissions.

#acledit /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22395'
  tag rid: 'SV-38790r1_rule'
  tag stig_id: 'GEN003410'
  tag gtitle: 'GEN003410'
  tag fix_id: 'F-32481r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
