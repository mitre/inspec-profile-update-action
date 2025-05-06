control 'SV-207217' do
  title 'The VPN Gateway must map the authenticated identity to the user account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

This requirement only applies to components where this is specific to the function of the device or has the concept of a user (e.g., VPN or ALG. This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the VPN Gateway maps the authenticated identity to the user account for PKI-based authentication.

If the VPN Gateway does not map the authenticated identity to the user account for PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to map the authenticated identity to the user account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7477r378272_chk'
  tag severity: 'medium'
  tag gid: 'V-207217'
  tag rid: 'SV-207217r608988_rule'
  tag stig_id: 'SRG-NET-000166-VPN-000590'
  tag gtitle: 'SRG-NET-000166'
  tag fix_id: 'F-7477r378273_fix'
  tag 'documentable'
  tag legacy: ['SV-106251', 'V-97113']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
