control 'SV-4109' do
  title 'The system is configured to allow dead gateway detection.'
  desc 'Allows TCP to perform dead-gateway detection, switching to a backup gateway if a number of connections to a gateway are experiencing difficulty. If enabled, an attacker could force internal traffic to be directed to a gateway outside the network. This setting applies to all network adapters, regardless of their individual settings.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> Security Options. If the value for “MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)” is not set to “Disabled”, then this is a finding. 

The policy referenced configures the following registry value.

Registry Path: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\ Value Name: EnableDeadGWDetect 
Value Type: REG_DWORD 
Value: 0'
  desc 'fix', 'Configure the system to disable dead gateway detection.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-278r1_chk'
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
