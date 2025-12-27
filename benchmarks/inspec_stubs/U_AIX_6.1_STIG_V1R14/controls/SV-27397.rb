control 'SV-27397' do
  title 'The at.deny file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.deny file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /var/adm/cron/at.deny
If the at.deny file is not owned by root, sys, or bin,  this is a finding.'
  desc 'fix', 'Change the owner of the at.deny file.
# chown root /var/adm/cron/at.deny'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28560r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4368'
  tag rid: 'SV-27397r1_rule'
  tag stig_id: 'GEN003480'
  tag gtitle: 'GEN003480'
  tag fix_id: 'F-24645r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
