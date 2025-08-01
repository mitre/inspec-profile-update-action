control 'SV-26759' do
  title 'The SSH daemon must be configured to not allow gateway ports.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server.  This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.  Gateway ports allow remote forwarded ports to bind to non-loopback addresses on the server.'
  desc 'check', "Check the SSH daemon configuration for the gateway ports setting.
# grep -i GatewayPorts /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned or the returned setting has a value evaluating to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and change or add the GatewayPorts setting to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27768r1_chk'
  tag severity: 'low'
  tag gid: 'V-22466'
  tag rid: 'SV-26759r1_rule'
  tag stig_id: 'GEN005517'
  tag gtitle: 'GEN005517'
  tag fix_id: 'F-24009r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
