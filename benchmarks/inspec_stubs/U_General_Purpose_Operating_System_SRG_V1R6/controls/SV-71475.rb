control 'SV-71475' do
  title 'The operating system must provide the capability to immediately disconnect or disable remote access to the operating system.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking place would not be immediately stopped.

Operating system remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions functions and the need to eliminate immediate or future remote access to organizational information systems.

The remote access functionality (e.g., RDP) may implement features such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.'
  desc 'check', 'Verify the operating system provides the capability to immediately disconnect or disable remote access to the operating system. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability to immediately disconnect or disable remote access to the operating system.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57215'
  tag rid: 'SV-71475r1_rule'
  tag stig_id: 'SRG-OS-000298-GPOS-00116'
  tag gtitle: 'SRG-OS-000298-GPOS-00116'
  tag fix_id: 'F-62131r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
