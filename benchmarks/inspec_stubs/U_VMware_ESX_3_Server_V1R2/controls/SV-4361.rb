control 'SV-4361' do
  title 'The cron.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the cron.allow file is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  desc 'check', 'Check the owner of the cron.allow file.  If the owner is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the owner of the cron.allow file to root, bin, or sys.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8223r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27370'
  tag rid: 'SV-4361r2_rule'
  tag stig_id: 'GEN003240'
  tag gtitle: 'GEN003240'
  tag fix_id: 'F-4272r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000888']
  tag nist: ['MA-4 (6)']
end
