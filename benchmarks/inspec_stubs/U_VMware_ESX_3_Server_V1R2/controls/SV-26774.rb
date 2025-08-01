control 'SV-26774' do
  title 'The SSH daemon must not permit tunnels.'
  desc 'OpenSSH has the ability to create network tunnels (layer-2 and layer-3) over an SSH connection.  This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', "Check the SSH daemon configuration for the PermitTunnel setting.
# grep -i PermitTunnel /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the PermitTunnel setting value to no.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27782r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22480'
  tag rid: 'SV-26774r1_rule'
  tag stig_id: 'GEN005531'
  tag gtitle: 'GEN005531'
  tag fix_id: 'F-24024r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
