control 'SV-226997' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', "Check the SSH daemon configuration for the StrictModes setting.
# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#'
If the setting is present and not set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and change the StrictModes setting value to yes or remove it entirely.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29159r485330_chk'
  tag severity: 'medium'
  tag gid: 'V-226997'
  tag rid: 'SV-226997r603265_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29147r485331_fix'
  tag 'documentable'
  tag legacy: ['SV-40400', 'V-22485']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
