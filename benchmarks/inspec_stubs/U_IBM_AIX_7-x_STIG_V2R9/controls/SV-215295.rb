control 'SV-215295' do
  title 'The AIX SSH daemon must be configured for IP filtering.'
  desc 'The SSH daemon must be configured for IP filtering to provide a layered defense against connection attempts from unauthorized addresses.'
  desc 'check', 'Check the TCP wrappers configuration files to determine if SSHD is configured to use TCP wrappers using commands: 

# grep sshd /etc/hosts.deny 
sshd : ALL

# grep sshd /etc/hosts.allow 
sshd : 10.10.20.*

If no entries are returned, the TCP wrappers are not configured for SSHD, this is a finding.'
  desc 'fix', 'Add appropriate IP restrictions for SSH to the "/etc/hosts.deny" and/or "/etc/hosts.allow" files. 

TCP Wrappers can be installed from the AIX Expansion Pack by installing fileset "netsec.options.tcpwrappers" using the following command (assume AIX Expansion Pack is mounted on /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log netsec.options.tcpwrappers'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16493r294336_chk'
  tag severity: 'medium'
  tag gid: 'V-215295'
  tag rid: 'SV-215295r508663_rule'
  tag stig_id: 'AIX7-00-002112'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16491r294337_fix'
  tag 'documentable'
  tag legacy: ['V-91679', 'SV-101777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
