control 'SV-207229' do
  title 'The VPN Gateway administrator accounts or security policy must be configured to allow the system administrator to immediately disconnect or disable remote access to devices and/or users when needed.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking progress would not be immediately stopped.

Remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of mission functions and the need to eliminate immediate or future remote access to organizational information systems.

The remote access functionality (e.g., VPN, ALG, and RAS) may implement features, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.'
  desc 'check', 'Configure the VPN Gateway for functionality, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack. 

Configure authorized system administrator accounts to allow them to disconnect or disable remote access to remove user under circumstances defined in the VPN SSP.

If the VPN Gateway administrator accounts or security policy is not configured to allow the system administrator to immediately disconnect or disable remote access to devices and/or users when needed, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway for functionality, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack. 

Configure authorized system administrator accounts to allow them to disconnect or disable remote access to remove user under circumstances defined in the VPN SSP.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7489r378308_chk'
  tag severity: 'medium'
  tag gid: 'V-207229'
  tag rid: 'SV-207229r856702_rule'
  tag stig_id: 'SRG-NET-000314-VPN-001060'
  tag gtitle: 'SRG-NET-000314'
  tag fix_id: 'F-7489r378309_fix'
  tag 'documentable'
  tag legacy: ['V-97137', 'SV-106275']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
