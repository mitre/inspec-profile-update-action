control 'SV-250593' do
  title 'The SSH daemon must be configured to not allow gateway ports.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs. Gateway ports allow remote forwarded ports to bind to non-loopback addresses on the server.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep -i GatewayPorts /etc/ssh/sshd_config

If "GatewayPorts" is not set to "no", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"GatewayPorts no"

Re-enable lock down mode.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54028r798776_chk'
  tag severity: 'low'
  tag gid: 'V-250593'
  tag rid: 'SV-250593r798778_rule'
  tag stig_id: 'GEN005517-ESXI5-000101'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53982r798777_fix'
  tag 'documentable'
  tag legacy: ['V-39250', 'SV-51066']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
