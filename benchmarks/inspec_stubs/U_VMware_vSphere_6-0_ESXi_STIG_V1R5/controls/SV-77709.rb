control 'SV-77709' do
  title 'The SSH daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer-2 and layer-3) over an SSH connection. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', 'To verify the PermitTunnel setting, run the following command: 

# grep -i "^PermitTunnel" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitTunnel no", this is a finding.'
  desc 'fix', 'To set the PermitTunnel setting, add or correct the following line in "/etc/ssh/sshd_config":

PermitTunnel no'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63219'
  tag rid: 'SV-77709r1_rule'
  tag stig_id: 'ESXI-06-000025'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
