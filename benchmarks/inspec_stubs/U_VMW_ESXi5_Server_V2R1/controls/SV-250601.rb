control 'SV-250601' do
  title 'The SSH client must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer-2 and layer-3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep Tunnel /etc/ssh/ssh_config

If the "Tunnel" attribute is not set to "no", this is a finding. If the /etc/ssh/ssh_config file does not exist or the Tunnel option is not set, this is not a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/ssh_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"Tunnel no"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54036r798800_chk'
  tag severity: 'medium'
  tag gid: 'V-250601'
  tag rid: 'SV-250601r798802_rule'
  tag stig_id: 'GEN005532-ESXI5-709'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53990r798801_fix'
  tag 'documentable'
  tag legacy: ['V-39270', 'SV-51086']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
