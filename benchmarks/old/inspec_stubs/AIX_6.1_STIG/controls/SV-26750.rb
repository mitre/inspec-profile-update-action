control 'SV-26750' do
  title 'The SSH daemon must only listen on management network addresses unless authorized for uses other than management.'
  desc 'The SSH daemon should only listen on network addresses designated for management traffic.  If the system has multiple network interfaces and SSH listens on addresses not designated for management traffic, the SSH service could be subject to unauthorized access.  If SSH is used for purposes other than management, such as providing an SFTP service, the list of approved listening addresses may be documented.'
  desc 'check', "Check the SSH daemon configuration for listening network addresses.
# grep -i Listen /etc/ssh/sshd_config | grep -v '^#'
If no configuration is returned, or if a returned Listen configuration contains addresses not designated for management traffic, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration to specify listening network addresses designated for management traffic.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22457'
  tag rid: 'SV-26750r1_rule'
  tag stig_id: 'GEN005504'
  tag gtitle: 'GEN005504'
  tag fix_id: 'F-24000r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000069']
  tag nist: ['AC-17 (3)']
end
