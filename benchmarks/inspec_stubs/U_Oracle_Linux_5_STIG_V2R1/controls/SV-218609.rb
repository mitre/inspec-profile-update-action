control 'SV-218609' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed."
  desc 'check', %q(Ask the SA if GSSAPI authentication is used for SSH authentication to the system. If so, this is not applicable.

Check the SSH daemon configuration for the GSSAPIAuthentication setting.

# grep -i GSSAPIAuthentication /etc/ssh/sshd_config | grep -v '^#'
 
If no lines are returned, or the setting is set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and set (add if necessary) a "GSSAPIAuthentication" directive set to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20084r562840_chk'
  tag severity: 'low'
  tag gid: 'V-218609'
  tag rid: 'SV-218609r603259_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20082r562841_fix'
  tag 'documentable'
  tag legacy: ['V-22473', 'SV-63877']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
