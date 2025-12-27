control 'SV-230380' do
  title 'RHEL 8 must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following commands:

$ sudo grep -i nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If this produces any output, it may be possible to log on with accounts with empty passwords.

$ sudo grep -i permitemptypasswords /etc/ssh/sshd_config

PermitEmptyPasswords no

If "PermitEmptyPasswords" is set to "yes", or If null passwords can be used, this is a finding.

Note: Manual changes to the listed files may be overwritten by the "authselect" program.'
  desc 'fix', 'Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" and add or edit the following line in "etc/ssh/sshd_config" to prevent logons with empty passwords.

PermitEmptyPasswords no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service

Note: Manual changes to the listed files may be overwritten by the "authselect" program.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33049r567886_chk'
  tag severity: 'high'
  tag gid: 'V-230380'
  tag rid: 'SV-230380r627750_rule'
  tag stig_id: 'RHEL-08-020330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33024r567887_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
