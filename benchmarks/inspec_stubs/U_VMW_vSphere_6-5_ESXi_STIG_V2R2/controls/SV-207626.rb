control 'SV-207626' do
  title 'The ESXi host SSH daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer-2 and layer-3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^PermitTunnel" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitTunnel no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitTunnel no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7881r364277_chk'
  tag severity: 'medium'
  tag gid: 'V-207626'
  tag rid: 'SV-207626r388482_rule'
  tag stig_id: 'ESXI-65-000025'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7881r364278_fix'
  tag 'documentable'
  tag legacy: ['SV-104083', 'V-93997']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
