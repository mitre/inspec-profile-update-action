control 'SV-221855' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not allow authentication using known hosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow authentication using known hosts authentication.

To determine how the SSH daemon's "IgnoreUserKnownHosts" option is set, run the following command:

# grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known hosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreUserKnownHosts yes

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23570r419637_chk'
  tag severity: 'medium'
  tag gid: 'V-221855'
  tag rid: 'SV-221855r603260_rule'
  tag stig_id: 'OL07-00-040380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23559r419638_fix'
  tag 'documentable'
  tag legacy: ['SV-108553', 'V-99449']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
