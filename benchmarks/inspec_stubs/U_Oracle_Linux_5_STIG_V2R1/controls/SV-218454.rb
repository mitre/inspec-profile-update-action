control 'SV-218454' do
  title 'The cron.deny file must be owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.'
  desc 'check', '# ls -lL /etc/cron.deny
If the cron.deny file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', '# chown root /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19929r562519_chk'
  tag severity: 'medium'
  tag gid: 'V-218454'
  tag rid: 'SV-218454r603259_rule'
  tag stig_id: 'GEN003260'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19927r562520_fix'
  tag 'documentable'
  tag legacy: ['V-4430', 'SV-64361']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
