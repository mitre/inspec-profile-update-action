control 'SV-77701' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'To verify the Compression setting, run the following command: 

# grep -i "^Compression" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Compression no", this is a finding.'
  desc 'fix', 'To set the Compression setting, add or correct the following line in "/etc/ssh/sshd_config":

Compression no'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63211'
  tag rid: 'SV-77701r1_rule'
  tag stig_id: 'ESXI-06-000021'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
