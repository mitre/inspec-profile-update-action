control 'SV-216119' do
  title 'The operating system must terminate the network connection associated with a communications session at the end of the session or after 10 minutes of inactivity.'
  desc 'This requirement applies to both internal and external networks. 

Terminating network connections associated with communications sessions means de-allocating associated TCP/IP address/port pairs at the operating system level.

The time period of inactivity may, as the organization deems necessary, be a set of time periods by type of network access or for specific accesses.'
  desc 'check', 'Determine if SSH is configured to disconnect sessions after 10 minutes of inactivity.

# grep ClientAlive /etc/ssh/sshd_config

If the output of this command is not:

ClientAliveInterval 600
ClientAliveCountMax 0

this is a finding.'
  desc 'fix', 'The root role is required.

Configure the system to disconnect SSH sessions after 10 minutes of inactivity.

Modify the sshd_config file:

# pfedit /etc/ssh/sshd_config

Modify or add the lines containing:

ClientAliveInterval
ClientAliveCountMax 

Change them to:

ClientAliveInterval 600
ClientAliveCountMax 0

Restart the SSH service:

# svcadm restart svc:/network/ssh'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17357r372739_chk'
  tag severity: 'low'
  tag gid: 'V-216119'
  tag rid: 'SV-216119r603268_rule'
  tag stig_id: 'SOL-11.1-040380'
  tag gtitle: 'SRG-OS-000163'
  tag fix_id: 'F-17355r372740_fix'
  tag 'documentable'
  tag legacy: ['V-48111', 'SV-60983']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
