control 'SV-226627' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the cron log file.
# ls -lL /var/cron/log
If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron log file.
# chmod 0600 /var/cron/log'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28788r483293_chk'
  tag severity: 'medium'
  tag gid: 'V-226627'
  tag rid: 'SV-226627r603265_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-28776r483294_fix'
  tag 'documentable'
  tag legacy: ['V-983', 'SV-27354']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
