control 'SV-215299' do
  title 'AIX SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Check the SSH daemon configuration for the "StrictModes" setting using command: 

# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#' 
StrictModes yes

If the setting is missing or is set to "no", this is a finding.)
  desc 'fix', 'Edit the "/etc/sshd/sshd_config" file and add or change the "StrictModes"  setting to "yes".

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16497r294348_chk'
  tag severity: 'medium'
  tag gid: 'V-215299'
  tag rid: 'SV-215299r508663_rule'
  tag stig_id: 'AIX7-00-002116'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16495r294349_fix'
  tag 'documentable'
  tag legacy: ['SV-101827', 'V-91729']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
