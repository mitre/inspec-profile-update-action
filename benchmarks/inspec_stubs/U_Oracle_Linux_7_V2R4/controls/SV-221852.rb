control 'SV-221852' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not allow authentication using rhosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow authentication using known hosts authentication.

To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

IgnoreRhosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known hosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreRhosts yes'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23567r419628_chk'
  tag severity: 'medium'
  tag gid: 'V-221852'
  tag rid: 'SV-221852r603260_rule'
  tag stig_id: 'OL07-00-040350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23556r419629_fix'
  tag 'documentable'
  tag legacy: ['SV-108547', 'V-99443']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
