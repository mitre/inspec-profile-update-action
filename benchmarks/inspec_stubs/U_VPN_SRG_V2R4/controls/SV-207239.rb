control 'SV-207239' do
  title 'The VPN Gateway must accept the Common Access Card (CAC) credential.'
  desc 'The use of Personal Identity Verification (PIV)  credentials facilitates standardization and reduces the risk of unauthorized access. DoD has mandated the use of the CAC as the PIV credential to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the VPN Gateway accepts PIV  credentials.

If the VPN Gateway does not accept the CAC credential, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to accept the CAC credential.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7499r573752_chk'
  tag severity: 'medium'
  tag gid: 'V-207239'
  tag rid: 'SV-207239r608988_rule'
  tag stig_id: 'SRG-NET-000341-VPN-001350'
  tag gtitle: 'SRG-NET-000341'
  tag fix_id: 'F-7499r573753_fix'
  tag 'documentable'
  tag legacy: ['V-97157', 'SV-106295']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
