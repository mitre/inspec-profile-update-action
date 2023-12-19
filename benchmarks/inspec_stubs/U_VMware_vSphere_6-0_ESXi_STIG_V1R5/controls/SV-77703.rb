control 'SV-77703' do
  title 'The SSH daemon must be configured to not allow gateway ports.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs. Gateway ports allow remote forwarded ports to bind to non-loopback addresses on the server.'
  desc 'check', 'To verify the GatewayPorts setting, run the following command: 

# grep -i "^GatewayPorts" /etc/ssh/sshd_config

If there is no output or the output is not exactly "GatewayPorts no", this is a finding.'
  desc 'fix', 'To set the GatewayPorts setting, add or correct the following line in "/etc/ssh/sshd_config":

GatewayPorts no'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63947r1_chk'
  tag severity: 'low'
  tag gid: 'V-63213'
  tag rid: 'SV-77703r1_rule'
  tag stig_id: 'ESXI-06-000022'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69131r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
