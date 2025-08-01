control 'SV-227755' do
  title 'The cron.deny file must have mode 0600 or less permissive.'
  desc 'If file permissions for cron.deny are more permissive than 0600, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the mode of the cron.deny file.
# ls -lL /etc/cron.d/cron.deny
If the cron.deny file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.deny file.
# chmod 0600 /etc/cron.d/cron.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29917r488849_chk'
  tag severity: 'medium'
  tag gid: 'V-227755'
  tag rid: 'SV-227755r603266_rule'
  tag stig_id: 'GEN003200'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29905r488850_fix'
  tag 'documentable'
  tag legacy: ['V-4358', 'SV-27359']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
