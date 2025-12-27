control 'SV-46108' do
  title 'The SSH daemon must be configured for IP filtering.'
  desc 'The SSH daemon must be configured for IP filtering to provide a layered defense against connection attempts from unauthorized addresses.'
  desc 'check', 'Check the TCP wrappers configuration files to determine if sshd is configured to use TCP wrappers.

Procedure:
# grep sshd /etc/hosts.deny
# grep sshd /etc/hosts.allow

If no entries are returned, the TCP wrappers are not configured for sshd, this is a finding.'
  desc 'fix', 'Add appropriate IP restrictions for SSH to the /etc/hosts.deny and/or /etc/hosts.allow files.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43365r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12022'
  tag rid: 'SV-46108r1_rule'
  tag stig_id: 'GEN005540'
  tag gtitle: 'GEN005540'
  tag fix_id: 'F-39449r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
