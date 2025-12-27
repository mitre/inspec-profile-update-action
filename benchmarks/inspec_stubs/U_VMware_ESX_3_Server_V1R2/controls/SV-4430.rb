control 'SV-4430' do
  title 'The cron.deny file must be owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.'
  desc 'check', 'Check the owner of the cron.deny file.  If the owner is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the owner of the cron.deny file to root, bin, or sys.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8224r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27375'
  tag rid: 'SV-4430r2_rule'
  tag stig_id: 'GEN003260'
  tag gtitle: 'GEN003260'
  tag fix_id: 'F-4329r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001009']
  tag nist: ['MP-2 (2)']
end
