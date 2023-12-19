control 'SV-227761' do
  title 'The at.deny file must have mode 0600 or less permissive.'
  desc 'The at daemon control files restrict access to scheduled job manipulation and must be protected.  Unauthorized modification of the at.deny file could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/cron.d/at.deny
If the file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the file.
# chmod 0600 /etc/cron.d/at.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29923r488867_chk'
  tag severity: 'medium'
  tag gid: 'V-227761'
  tag rid: 'SV-227761r603266_rule'
  tag stig_id: 'GEN003252'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29911r488868_fix'
  tag 'documentable'
  tag legacy: ['V-22392', 'SV-26556']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
