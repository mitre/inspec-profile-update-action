control 'SV-218610' do
  title 'The SSH client must not permit GSSAPI authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed."
  desc 'check', %q(The default setting for GSSAPIAuthentication  is "no".

Check for a change from the default.

# grep -i GSSAPIAuthentication /etc/ssh/ssh_config | grep -v '^#'

If the setting is "yes" this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and set the GSSAPIAuthentication" directive set to "no".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20085r562843_chk'
  tag severity: 'low'
  tag gid: 'V-218610'
  tag rid: 'SV-218610r603259_rule'
  tag stig_id: 'GEN005525'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20083r562844_fix'
  tag 'documentable'
  tag legacy: ['V-22474', 'SV-63953']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
