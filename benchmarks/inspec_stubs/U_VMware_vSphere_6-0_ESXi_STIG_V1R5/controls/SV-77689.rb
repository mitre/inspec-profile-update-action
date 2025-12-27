control 'SV-77689' do
  title 'The SSH daemon must not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(To verify how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command: 

# grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitEmptyPasswords no", this is a finding.)
  desc 'fix', 'To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config": 

PermitEmptyPasswords no'
  impact 0.7
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63933r1_chk'
  tag severity: 'high'
  tag gid: 'V-63199'
  tag rid: 'SV-77689r1_rule'
  tag stig_id: 'ESXI-06-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
