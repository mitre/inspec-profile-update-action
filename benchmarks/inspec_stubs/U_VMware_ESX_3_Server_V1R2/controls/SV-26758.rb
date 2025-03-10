control 'SV-26758' do
  title 'The SSH client must be configured to not allow TCP forwarding.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server.  This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', %q(Check the SSH client configuration for the TCP forwarding setting.
# egrep -i "LocalForward|RemoteForward" /etc/ssh/ssh_config | grep -v '^#' 
If any uncommented lines are returned, this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and change or add the AllowTCPForwarding setting to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27767r1_chk'
  tag severity: 'low'
  tag gid: 'V-22465'
  tag rid: 'SV-26758r1_rule'
  tag stig_id: 'GEN005516'
  tag gtitle: 'GEN005516'
  tag fix_id: 'F-24008r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
