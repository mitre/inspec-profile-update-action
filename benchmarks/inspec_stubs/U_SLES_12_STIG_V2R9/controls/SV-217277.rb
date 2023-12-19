control 'SV-217277' do
  title 'The SUSE operating system SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'Verify the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Check that the SSH daemon performs strict mode checking of home directory configuration files with the following command:

# sudo grep -i strictmodes /etc/ssh/sshd_config

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes":

StrictModes yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18505r369987_chk'
  tag severity: 'medium'
  tag gid: 'V-217277'
  tag rid: 'SV-217277r603262_rule'
  tag stig_id: 'SLES-12-030230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18503r369988_fix'
  tag 'documentable'
  tag legacy: ['SV-92163', 'V-77467']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
