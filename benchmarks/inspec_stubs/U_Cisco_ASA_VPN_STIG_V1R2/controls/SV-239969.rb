control 'SV-239969' do
  title 'The Cisco ASA remote access VPN server must be configured to map the distinguished name (DN) from the client’s certificate to entries in the authentication server to determine authorization to access the network.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

This requirement only applies to components where this is specific to the function of the device or has the concept of a user (e.g., VPN or ALG). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Review the tunnel group configured for remote access and verify that the DN or UPN from the client’s certificate is used to map to entries in the authentication server to determine authorization as shown in the example below.

tunnel-group ANY_CONNECT type remote-access
tunnel-group ANY_CONNECT general-attributes
 authorization-server-group LDAP
 authorization-required
 username-from-certificate use-entire-name

If the ASA is not configured to map the distinguished name from the client’s certificate to entries in the authentication server to determine authorization, this is a finding.'
  desc 'fix', 'Configure the ASA to map the distinguished name from the client’s certificate to entries in the authentication server to determine authorization as shown in the example.

ASA2(config)# tunnel-group ANY_CONNECT general-attributes
ASA2(config-tunnel-general)# authorization-required 
ASA2(config-tunnel-general)# authorization-server-group LDAP
ASA2(config-tunnel-general)# username-from-certificate username-from-certificate use-entire-name
ASA2(config-tunnel-general)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43202r666311_chk'
  tag severity: 'medium'
  tag gid: 'V-239969'
  tag rid: 'SV-239969r666313_rule'
  tag stig_id: 'CASA-VN-000450'
  tag gtitle: 'SRG-NET-000166-VPN-000590'
  tag fix_id: 'F-43161r666312_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
