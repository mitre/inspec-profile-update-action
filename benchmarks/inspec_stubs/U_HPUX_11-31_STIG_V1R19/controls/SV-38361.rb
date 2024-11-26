control 'SV-38361' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /var/adm/cron/log

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /var/adm/cron/log'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36472r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22388'
  tag rid: 'SV-38361r1_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'GEN003190'
  tag fix_id: 'F-31815r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
