control 'SV-218446' do
  title 'The cron.deny file must have mode 0600 or less permissive.'
  desc 'If file permissions for cron.deny are more permissive than 0600, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the mode of the cron.deny file.
# ls -lL /etc/cron.deny
If the cron.deny file does not exist this is not a finding.
If the cron.deny file exists and the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.deny file.
# chmod 0600 /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19921r562495_chk'
  tag severity: 'medium'
  tag gid: 'V-218446'
  tag rid: 'SV-218446r603259_rule'
  tag stig_id: 'GEN003200'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19919r562496_fix'
  tag 'documentable'
  tag legacy: ['V-4358', 'SV-64329']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
