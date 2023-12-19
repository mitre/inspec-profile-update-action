control 'SV-217274' do
  title 'The SUSE operating system SSH daemon must be configured to not allow authentication using known hosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon is configured to not allow authentication using known hosts authentication.

To determine how the SSH daemon's "IgnoreUserKnownHosts" option is set, run the following command:

# sudo grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon to not allow authentication using known hosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreUserKnownHosts yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18502r369978_chk'
  tag severity: 'medium'
  tag gid: 'V-217274'
  tag rid: 'SV-217274r603262_rule'
  tag stig_id: 'SLES-12-030200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18500r369979_fix'
  tag 'documentable'
  tag legacy: ['V-77461', 'SV-92157']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
