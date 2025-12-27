control 'SV-239981' do
  title 'The Cisco VPN remote access server must be configured to accept Common Access Card (CAC) credential credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the ASA accepts CAC credentials as shown in the example below.

tunnel-group ANY_CONNECT type remote-access
tunnel-group ANY_CONNECT webvpn-attributes
 authentication certificate

If the ASA does not accept PIV credentials, this is a finding.'
  desc 'fix', 'Configure the ASA to accept CAC credentials as shown in the example below.

ASA1(config)# tunnel-group ANY_CONNECT webvpn-attributes
ASA1(config-tunnel-webvpn)# authentication certificate 
ASA1(config-tunnel-webvpn)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43214r666347_chk'
  tag severity: 'medium'
  tag gid: 'V-239981'
  tag rid: 'SV-239981r666349_rule'
  tag stig_id: 'CASA-VN-000660'
  tag gtitle: 'SRG-NET-000341-VPN-001350'
  tag fix_id: 'F-43173r666348_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
