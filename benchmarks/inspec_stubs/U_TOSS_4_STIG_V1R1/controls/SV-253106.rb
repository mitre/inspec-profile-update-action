control 'SV-253106' do
  title 'The TOSS SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo grep -i strictmodes /etc/ssh/sshd_config

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to perform strict mode checking of home directory configuration files. Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes":

StrictModes yes

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56559r824988_chk'
  tag severity: 'medium'
  tag gid: 'V-253106'
  tag rid: 'SV-253106r824990_rule'
  tag stig_id: 'TOSS-04-040650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56509r824989_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
