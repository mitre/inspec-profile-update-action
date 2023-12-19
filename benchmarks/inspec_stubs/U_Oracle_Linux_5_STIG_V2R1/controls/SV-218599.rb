control 'SV-218599' do
  title 'The SSH daemon must only listen on management network addresses unless authorized for uses other than management.'
  desc 'The SSH daemon should only listen on network addresses designated for management traffic.  If the system has multiple network interfaces and SSH listens on addresses not designated for management traffic, the SSH service could be subject to unauthorized access.  If SSH is used for purposes other than management, such as providing an SFTP service, the list of approved listening addresses may be documented.'
  desc 'check', "Ask the SA to identify which interfaces on the system are designated for management traffic.  If all interfaces on the system are authorized for management traffic, this is not applicable.

Check the SSH daemon configuration for listening network addresses.

# grep -i Listen /etc/ssh/sshd_config | grep -v '^#'

If no configuration is returned, or if a returned 'Listen' configuration contains addresses not designated for management traffic, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration to specify listening network addresses designated for management traffic.

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20074r562834_chk'
  tag severity: 'medium'
  tag gid: 'V-218599'
  tag rid: 'SV-218599r603259_rule'
  tag stig_id: 'GEN005504'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20072r562835_fix'
  tag 'documentable'
  tag legacy: ['V-22457', 'SV-63553']
  tag cci: ['CCI-000069', 'CCI-000366']
  tag nist: ['AC-17 (3)', 'CM-6 b']
end
