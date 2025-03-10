control 'SV-226999' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', "Check the SSH daemon configuration for the Compression setting.
# grep -i Compression /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the Compression setting value to no or delayed.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29161r485336_chk'
  tag severity: 'medium'
  tag gid: 'V-226999'
  tag rid: 'SV-226999r603265_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29149r485337_fix'
  tag 'documentable'
  tag legacy: ['V-22488', 'SV-26787']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
