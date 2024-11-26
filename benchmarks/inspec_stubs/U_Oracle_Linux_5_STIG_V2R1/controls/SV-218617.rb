control 'SV-218617' do
  title 'The SSH daemon must be configured for IP filtering.'
  desc 'The SSH daemon must be configured for IP filtering to provide a layered defense against connection attempts from unauthorized addresses.'
  desc 'check', 'Check the TCP wrappers configuration files to determine if sshd is configured to use TCP wrappers.

Procedure:
# grep sshd /etc/hosts.deny
# grep sshd /etc/hosts.allow

If no entries are returned, the TCP wrappers are not configured for sshd, this is a finding.'
  desc 'fix', 'Add appropriate IP restrictions for SSH to the /etc/hosts.deny and/or /etc/hosts.allow files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20092r556049_chk'
  tag severity: 'medium'
  tag gid: 'V-218617'
  tag rid: 'SV-218617r603259_rule'
  tag stig_id: 'GEN005540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20090r556050_fix'
  tag 'documentable'
  tag legacy: ['V-12022', 'SV-64101']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
