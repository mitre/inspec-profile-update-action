control 'SV-227739' do
  title 'The cron.allow file must have mode 0600 or less permissive.'
  desc 'A cron.allow file that is readable and/or writable by other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check mode of the cron.allow file.

Procedure:
# ls -lL /etc/cron.d/cron.allow

If either file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.allow file to 0600.

Procedure:
# chmod 0600 /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29901r488801_chk'
  tag severity: 'medium'
  tag gid: 'V-227739'
  tag rid: 'SV-227739r603266_rule'
  tag stig_id: 'GEN002980'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29889r488802_fix'
  tag 'documentable'
  tag legacy: ['V-975', 'SV-27323']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
