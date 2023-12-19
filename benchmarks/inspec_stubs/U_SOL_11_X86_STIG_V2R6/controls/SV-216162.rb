control 'SV-216162' do
  title 'The operating system must terminate all sessions and network connections when non-local maintenance is completed.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

The operating system needs to ensure all sessions and network connections are terminated when non-local maintenance is completed.'
  desc 'check', 'Determine if SSH is configured to disconnect sessions after 10 minutes of inactivity.

# grep ClientAlive /etc/ssh/sshd_config

If the output of this command is not:

ClientAliveInterval 600
ClientAliveCountMax 0

this is a finding.'
  desc 'fix', 'The root role is required.

Configure the system to disconnect SSH sessions after 10 minutes of inactivity.

# pfedit /etc/ssh/sshd_config

Insert the two lines:

ClientAliveInterval 600
ClientAliveCountMax 0

Restart the SSH service with the new configuration.

# svcadm restart svc:/network/ssh'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17400r372868_chk'
  tag severity: 'medium'
  tag gid: 'V-216162'
  tag rid: 'SV-216162r603268_rule'
  tag stig_id: 'SOL-11.1-050460'
  tag gtitle: 'SRG-OS-000126'
  tag fix_id: 'F-17398r372869_fix'
  tag 'documentable'
  tag legacy: ['V-48195', 'SV-61067']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
