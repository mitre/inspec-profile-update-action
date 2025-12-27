control 'SV-975' do
  title 'The cron.allow file must have mode 0600 or less permissive.'
  desc 'A cron.allow file that is readable and/or writable by other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check the mode of the cron.allow file.  If the file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.allow file to 0600.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-787r2_chk'
  tag severity: 'medium'
  tag gid: 'V-975'
  tag rid: 'SV-975r2_rule'
  tag stig_id: 'GEN002980'
  tag gtitle: 'GEN002980'
  tag fix_id: 'F-1129r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
