control 'SV-239280' do
  title 'The ESXi host SSH daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer 2 and layer 3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs).'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^PermitTunnel" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitTunnel no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitTunnel no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42513r674767_chk'
  tag severity: 'medium'
  tag gid: 'V-239280'
  tag rid: 'SV-239280r674769_rule'
  tag stig_id: 'ESXI-67-000025'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42472r674768_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
