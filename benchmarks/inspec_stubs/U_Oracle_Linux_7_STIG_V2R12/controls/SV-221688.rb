control 'SV-221688' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config
PermitEmptyPasswords no

If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.

If the required value is not set, this is a finding.)
  desc 'fix', 'To explicitly disallow remote logon from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no

The SSH service must be restarted for changes to take effect. Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23403r419136_chk'
  tag severity: 'high'
  tag gid: 'V-221688'
  tag rid: 'SV-221688r603260_rule'
  tag stig_id: 'OL07-00-010300'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-23392r419137_fix'
  tag 'documentable'
  tag legacy: ['SV-108219', 'V-99115']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
