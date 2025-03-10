control 'SV-216355' do
  title 'Login must not be permitted with empty/null passwords for SSH.'
  desc 'Permitting login without a password is inherently risky.'
  desc 'check', 'Determine if empty/null passwords are allowed for the SSH service.

# grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

If the output of this command is not:

PermitEmptyPasswords no

this is a finding.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file

# pfedit /etc/ssh/sshd_config

Locate the line containing:

PermitEmptyPasswords

Change it to:

PermitEmptyPasswords no

Restart the SSH service.

# svcadm restart svc:/network/ssh'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17591r371153_chk'
  tag severity: 'high'
  tag gid: 'V-216355'
  tag rid: 'SV-216355r603267_rule'
  tag stig_id: 'SOL-11.1-040370'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17589r371154_fix'
  tag 'documentable'
  tag legacy: ['SV-60979', 'V-48107']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
