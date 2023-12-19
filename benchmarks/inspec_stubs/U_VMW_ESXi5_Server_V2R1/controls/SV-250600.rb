control 'SV-250600' do
  title 'The SSH daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer-2 and layer-3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep PermitTunnel /etc/ssh/sshd_config

If the command returns nothing, or the returned "PermitTunnel" attribute is not set to "no", this is a finding.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"PermitTunnel no"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54035r798797_chk'
  tag severity: 'medium'
  tag gid: 'V-250600'
  tag rid: 'SV-250600r798799_rule'
  tag stig_id: 'GEN005531-ESXI5-000108'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53989r798798_fix'
  tag 'documentable'
  tag legacy: ['SV-51084', 'V-39268']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
