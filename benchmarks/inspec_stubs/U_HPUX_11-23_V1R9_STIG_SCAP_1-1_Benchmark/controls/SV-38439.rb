control 'SV-38439' do
  title 'The cron.deny file must be owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.'
  desc 'fix', '# chown root /var/adm/cron/cron.deny'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4430'
  tag rid: 'SV-38439r1_rule'
  tag stig_id: 'GEN003260'
  tag gtitle: 'GEN003260'
  tag fix_id: 'F-31810r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
