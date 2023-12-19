control 'SV-207240' do
  title 'The VPN Gateway must electronically verify the Common Access Card (CAC) credential.'
  desc 'DoD has mandated the use of the CAC as the Personal Identity Verification (PIV) credential to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the VPN Gateway electronically verifies the CAC credential.

If the VPN Gateway does not electronically verify Personal Identity Verification (PIV) credentials, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to electronically verify the CAC credential.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7500r573755_chk'
  tag severity: 'medium'
  tag gid: 'V-207240'
  tag rid: 'SV-207240r608988_rule'
  tag stig_id: 'SRG-NET-000342-VPN-001360'
  tag gtitle: 'SRG-NET-000342'
  tag fix_id: 'F-7500r573756_fix'
  tag 'documentable'
  tag legacy: ['V-97159', 'SV-106297']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
