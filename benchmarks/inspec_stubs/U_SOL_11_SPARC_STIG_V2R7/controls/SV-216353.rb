control 'SV-216353' do
  title 'The rhost-based authentication for SSH must be disabled.'
  desc 'Setting this parameter forces users to enter a password when authenticating with SSH.'
  desc 'check', 'Determine if rhost-based authentication is enabled.

# grep "^IgnoreRhosts" /etc/ssh/sshd_config

If the output is produced and it is not:

IgnoreRhosts yes

this is a finding.

If the IgnoreRhosts line does not exist in the file, the default setting of "Yes" is automatically used and there is no finding.'
  desc 'fix', 'The root role is required.

Modify the sshd_config file

# pfedit /etc/ssh/sshd_config

Locate the line containing:

IgnoreRhosts

Change it to:

IgnoreRhosts yes

Restart the SSH service.

# svcadm restart svc:/network/ssh


This action will only set the IgnoreRhosts line if it already exists in the file to ensure that it is set to the proper value. If the IgnoreRhosts line does not exist in the file, the default setting of "Yes" is automatically used, so no additional changes are needed.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17589r371147_chk'
  tag severity: 'medium'
  tag gid: 'V-216353'
  tag rid: 'SV-216353r603267_rule'
  tag stig_id: 'SOL-11.1-040350'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17587r371148_fix'
  tag 'documentable'
  tag legacy: ['SV-60973', 'V-48101']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
