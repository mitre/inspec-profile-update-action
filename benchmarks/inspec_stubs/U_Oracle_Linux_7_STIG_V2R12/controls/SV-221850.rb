control 'SV-221850' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Check the version of the operating system with the following command:

# cat /etc/oracle-release

If the release is 7.4 or newer this requirement is Not Applicable.

Verify the SSH daemon does not allow authentication using RSA rhosts authentication.

To determine how the SSH daemon's "RhostsRSAAuthentication" option is set, run the following command:

# grep RhostsRSAAuthentication /etc/ssh/sshd_config
RhostsRSAAuthentication no

If the value is returned as "yes", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using RSA rhosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

RhostsRSAAuthentication no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23565r419622_chk'
  tag severity: 'medium'
  tag gid: 'V-221850'
  tag rid: 'SV-221850r603260_rule'
  tag stig_id: 'OL07-00-040330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23554r419623_fix'
  tag 'documentable'
  tag legacy: ['SV-108543', 'V-99439']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
