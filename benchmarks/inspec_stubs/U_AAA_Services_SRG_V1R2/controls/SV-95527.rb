control 'SV-95527' do
  title 'AAA Services must be configured to use protocols that encrypt credentials when authenticating clients, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Authentication protection of the client credentials (specifically the password or shared secret) prevents unauthorized access to resources. The RADIUS protocol encrypts the password field in the access-request packet, from the client to the AAA server. The remainder of the packet is unencrypted. Other information, such as username, authorized services, and accounting, can be captured by a third-party. TACACS+ encrypts the entire body of the packet but leaves a standard TACACS+ header. Within the header is a field that indicates whether the body is encrypted or not. Other protocols have similar protections. When unencrypted credentials are passed, adversaries can gain access to resources.'
  desc 'check', 'Verify AAA Services are configured to use protocols that encrypt credentials when authenticating clients. Both the RADIUS and TACACS+ protocols are acceptable when configured to perform encryption. For any protocol implemented, the PPSM CAL and vulnerability assessments must be reviewed to ensure the protocols are properly configured.

If AAA Services are not configured to use protocols that encrypt credentials when authenticating clients, as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Configure AAA Services to use protocols that encrypt credentials when authenticating clients. Both the RADIUS and TACACS+ protocols are acceptable when configured to perform encryption. For any protocol implemented, the PPSM CAL and vulnerability assessments must be reviewed to ensure the protocols are properly configured.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80553r3_chk'
  tag severity: 'high'
  tag gid: 'V-80817'
  tag rid: 'SV-95527r1_rule'
  tag stig_id: 'SRG-APP-000142-AAA-000020'
  tag gtitle: 'SRG-APP-000142-AAA-000020'
  tag fix_id: 'F-87671r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
