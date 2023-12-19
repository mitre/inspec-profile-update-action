control 'SV-207436' do
  title 'The VMM must provide the capability to immediately disconnect or disable remote access to the information system.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking place would not be immediately stopped.

VMM remote access functionality must have the capability to immediately disconnect current users remotely accessing the VMM and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions functions and the need to eliminate immediate or future remote access to organizational VMMs.

The remote access functionality (e.g., RDP) may implement features, such as automatic disconnect (or user-initiated disconnect), in case of adverse information based on an indicator of compromise or attack.'
  desc 'check', 'Verify the VMM provides the capability to immediately disconnect or disable remote access to the information system.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide the capability to immediately disconnect or disable remote access to the information system.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7693r365718_chk'
  tag severity: 'medium'
  tag gid: 'V-207436'
  tag rid: 'SV-207436r854611_rule'
  tag stig_id: 'SRG-OS-000298-VMM-001050'
  tag gtitle: 'SRG-OS-000298'
  tag fix_id: 'F-7693r365719_fix'
  tag 'documentable'
  tag legacy: ['V-57073', 'SV-71333']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
