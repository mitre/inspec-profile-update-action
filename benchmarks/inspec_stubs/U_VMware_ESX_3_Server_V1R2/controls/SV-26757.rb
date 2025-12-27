control 'SV-26757' do
  title 'The SSH daemon must be configured to not allow TCP connection forwarding.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server.  This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', "Check the SSH daemon configuration for the TCP connection forwarding setting.
# grep -i AllowTCPForwarding /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned setting has a value evaluating to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and change or add the AllowTCPForwarding setting to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27766r1_chk'
  tag severity: 'low'
  tag gid: 'V-22464'
  tag rid: 'SV-26757r1_rule'
  tag stig_id: 'GEN005515'
  tag gtitle: 'GEN005515'
  tag fix_id: 'F-24007r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN005515'
  tag mitigation_control: 'If TCP connection forwarding is required the risk of unauthorized use of this feature can be mitigated by placing restrictions on which users are permitted to use it. For instance, OpenSSH provides conditional configuration blocks (using the Match keyword) used to limit TCP connection forwarding based on user, group, host, or address.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
