control 'SV-40723' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', %q(Check the SSH daemon configuration for the Compression setting.

# grep -i Compression /etc/ssh/sshd_config | grep -v '^#'

If the setting is present and set to "yes", this is a finding.  If the setting is absent or set to "no" or "delayed", this is not a finding.)
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and remove the Compression setting or set the Compression setting to "delayed" or "no".'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39454r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22488'
  tag rid: 'SV-40723r1_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'GEN005539'
  tag fix_id: 'F-34582r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
