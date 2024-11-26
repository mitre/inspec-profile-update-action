control 'SV-4109' do
  title 'The system is configured to allow dead gateway detection.'
  desc 'Allows TCP to peform dead-gateway detection, switching to a backup gateway if a number of connections to a gateway are experiencing difficulty. If enabled, an attacker could force internal traffic to be directed to a gateway outside the network. This setting applies to all network adapters, regardless of their individual settings.'
  desc 'fix', 'Configure the system to disable dead gateway detection.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-4109'
  tag rid: 'SV-4109r1_rule'
  tag gtitle: 'Disable Dead Gateway Detection'
  tag fix_id: 'F-5712r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
