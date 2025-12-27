control 'SV-207350' do
  title 'The VMM must monitor remote access methods automatically.'
  desc 'Remote access services, such as those providing remote access to network devices and VMMs, which lack automated capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD VMMs by an authorized user (or another VMM) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of VMM components.'
  desc 'check', 'Verify the VMM monitors remote access methods automatically. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to monitor remote access methods automatically.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7607r365460_chk'
  tag severity: 'medium'
  tag gid: 'V-207350'
  tag rid: 'SV-207350r378607_rule'
  tag stig_id: 'SRG-OS-000032-VMM-000130'
  tag gtitle: 'SRG-OS-000032'
  tag fix_id: 'F-7607r365461_fix'
  tag 'documentable'
  tag legacy: ['V-56871', 'SV-71131']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
