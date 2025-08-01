control 'SV-46107' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43364r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22488'
  tag rid: 'SV-46107r2_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'GEN005539'
  tag fix_id: 'F-39448r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
