control 'SV-250594' do
  title 'The SSH client must be configured to not allow gateway ports.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs. Gateway ports allow remote forwarded ports to bind to non-loopback addresses on the server.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell. Check the SSH client configuration for the gateway ports setting.
# grep -i GatewayPorts /etc/ssh/ssh_config | grep -v '^#'

If "GatewayPorts" is set to "yes", this is a finding. If the /etc/ssh/ssh_config file does not exist, this is not a finding.

Re-enable lock down mode.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell. Edit the SSH client configuration and add/modify the "GatewayPorts" configuration, setting it to "no".
# vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54029r798779_chk'
  tag severity: 'low'
  tag gid: 'V-250594'
  tag rid: 'SV-250594r798781_rule'
  tag stig_id: 'GEN005518-ESXI5-704'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53983r798780_fix'
  tag 'documentable'
  tag legacy: ['SV-51067', 'V-39251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
