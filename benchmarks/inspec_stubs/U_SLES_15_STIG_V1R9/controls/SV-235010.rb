control 'SV-235010' do
  title 'The SUSE operating system SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'Verify the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Check that the SSH daemon performs strict mode checking of home directory configuration files with the following command:

> sudo grep -i strictmodes /etc/ssh/sshd_config

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes":

StrictModes yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38198r619299_chk'
  tag severity: 'medium'
  tag gid: 'V-235010'
  tag rid: 'SV-235010r622137_rule'
  tag stig_id: 'SLES-15-040260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38161r619300_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
