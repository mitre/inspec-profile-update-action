control 'SV-38364' do
  title 'The at directory must not have an extended ACL.'
  desc 'If the at directory has an extended ACL, unauthorized users could be allowed to view or to edit files containing sensitive information within the at directory. Unauthorized modifications could result in Denial of Service to authorized at jobs.'
  desc 'check', 'Check the permissions of the directory.
# ls -lLd /var/spool/cron/atjobs

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the directory.
# chacl -z /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36479r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22395'
  tag rid: 'SV-38364r1_rule'
  tag stig_id: 'GEN003410'
  tag gtitle: 'GEN003410'
  tag fix_id: 'F-31823r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
