control 'SV-227892' do
  title 'The SSH daemon must only listen on management network addresses unless authorized for uses other than management.'
  desc 'The SSH daemon should only listen on network addresses designated for management traffic.  If the system has multiple network interfaces and SSH listens on addresses not designated for management traffic, the SSH service could be subject to unauthorized access.  If SSH is used for purposes other than management, such as providing an SFTP service, the list of approved listening addresses may be documented.'
  desc 'check', "Check the SSH daemon configuration for listening network addresses.
# grep -i Listen /etc/ssh/sshd_config | grep -v '^#'
If no configuration is returned, or if a returned Listen configuration contains addresses not designated for management traffic, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration to specify listening network addresses designated for management traffic.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30054r490081_chk'
  tag severity: 'medium'
  tag gid: 'V-227892'
  tag rid: 'SV-227892r603266_rule'
  tag stig_id: 'GEN005504'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30042r490082_fix'
  tag 'documentable'
  tag legacy: ['V-22457', 'SV-26750']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
