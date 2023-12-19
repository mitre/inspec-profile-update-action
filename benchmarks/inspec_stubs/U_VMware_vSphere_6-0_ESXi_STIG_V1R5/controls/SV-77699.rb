control 'SV-77699' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', 'To verify the StrictModes setting, run the following command: 

# grep -i "^StrictModes" /etc/ssh/sshd_config

If there is no output or the output is not exactly "StrictModes yes", this is a finding.'
  desc 'fix', 'To set the StrictModes setting, add or correct the following line in "/etc/ssh/sshd_config":

StrictModes yes'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63209'
  tag rid: 'SV-77699r1_rule'
  tag stig_id: 'ESXI-06-000020'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
