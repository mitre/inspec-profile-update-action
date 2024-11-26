control 'SV-207623' do
  title 'The ESXi host SSH daemon must be configured to not allow gateway ports.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs. Gateway ports allow remote forwarded ports to bind to non-loopback addresses on the server.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^GatewayPorts" /etc/ssh/sshd_config

If there is no output or the output is not exactly "GatewayPorts no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

GatewayPorts no'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7878r364268_chk'
  tag severity: 'low'
  tag gid: 'V-207623'
  tag rid: 'SV-207623r388482_rule'
  tag stig_id: 'ESXI-65-000022'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7878r364269_fix'
  tag 'documentable'
  tag legacy: ['SV-104077', 'V-93991']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
