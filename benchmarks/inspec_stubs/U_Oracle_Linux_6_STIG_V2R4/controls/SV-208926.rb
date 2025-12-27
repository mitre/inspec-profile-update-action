control 'SV-208926' do
  title 'The SSH daemon must not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command: 

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.)
  desc 'fix', 'To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config": 

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9179r357758_chk'
  tag severity: 'high'
  tag gid: 'V-208926'
  tag rid: 'SV-208926r603263_rule'
  tag stig_id: 'OL6-00-000239'
  tag gtitle: 'SRG-OS-000106'
  tag fix_id: 'F-9179r357759_fix'
  tag 'documentable'
  tag legacy: ['SV-65007', 'V-50801']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
