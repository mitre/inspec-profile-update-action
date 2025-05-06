control 'SV-250592' do
  title 'The SSH client must be configured to not allow TCP forwarding.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep Forward /etc/ssh/ssh_config

Re-enable lock down mode.

If any of the following attributes (ForwardAgent, ForwardX11, or ForwardX11Trusted) exist and are not set to "no", this is a finding. If the /etc/ssh/ssh_config file does not exist, this is not a finding.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/ssh_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"ForwardAgent no"
"ForwardX11 no"
"ForwardX11Trusted no"

Re-enable lock down mode.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54027r798773_chk'
  tag severity: 'low'
  tag gid: 'V-250592'
  tag rid: 'SV-250592r798775_rule'
  tag stig_id: 'GEN005516-ESXI5-703'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53981r798774_fix'
  tag 'documentable'
  tag legacy: ['SV-51065', 'V-39249']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
