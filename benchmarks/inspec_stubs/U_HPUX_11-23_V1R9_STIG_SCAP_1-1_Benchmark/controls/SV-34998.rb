control 'SV-34998' do
  title 'The at.deny file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.deny file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'fix', 'Change the owner of the at.deny file.
# chown root /usr/lib/cron/at.deny'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4368'
  tag rid: 'SV-34998r1_rule'
  tag stig_id: 'GEN003480'
  tag gtitle: 'GEN003480'
  tag fix_id: 'F-30203r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
