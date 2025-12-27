control 'SV-218429' do
  title 'The cron.allow file must have mode 0600 or less permissive.'
  desc 'A readable and/or writable cron.allow file by users other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check mode of the cron.allow file.

Procedure:
# ls -lL /etc/cron.allow

If the file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.allow file to 0600.

Procedure:
# chmod 0600 /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19904r562447_chk'
  tag severity: 'medium'
  tag gid: 'V-218429'
  tag rid: 'SV-218429r603259_rule'
  tag stig_id: 'GEN002980'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19902r562448_fix'
  tag 'documentable'
  tag legacy: ['V-975', 'SV-64411']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
