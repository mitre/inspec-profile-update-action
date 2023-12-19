control 'SV-218616' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Check the SSH daemon configuration for the compression setting.

# grep -i Compression /etc/ssh/sshd_config | egrep "no|delayed"

If the setting is missing or is commented out, this is a finding.

If the setting is present but is not set to "no" or "delayed", this is a finding.'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "Compression" setting value to "no" or "delayed".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20091r556046_chk'
  tag severity: 'medium'
  tag gid: 'V-218616'
  tag rid: 'SV-218616r603259_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20089r556047_fix'
  tag 'documentable'
  tag legacy: ['V-22488', 'SV-64089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
