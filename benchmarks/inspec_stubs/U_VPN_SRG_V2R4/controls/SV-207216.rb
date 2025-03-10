control 'SV-207216' do
  title 'The Remote Access VPN Gateway must use a separate authentication server (e.g., LDAP, RADIUS, TACACS+) to perform user authentication.'
  desc 'The VPN interacts directly with public networks and devices and should not contain user authentication information for all users. AAA network security services provide the primary framework through which a network administrator can set up access control and authorization on network points of entry or network access servers. It is not advisable to configure access control on the VPN gateway or remote access server. Separation of services provides added assurance to the network if the access control server is compromised.'
  desc 'check', 'Verify the Remote Access VPN Gateway is configured to use a physically separate authentication server (e.g., LDAP, RADIUS, TACACS+) to perform user authentication.

If the Remote Access VPN Gateway does not use a separate authentication server (e.g., LDAP, RADIUS, TACACS+) to perform user authentication, this is a finding.'
  desc 'fix', 'Configure the Remote Access VPN Gateway to use a separate authentication server (e.g., LDAP, RADIUS, TACACS+) to perform user authentication.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7476r378269_chk'
  tag severity: 'medium'
  tag gid: 'V-207216'
  tag rid: 'SV-207216r608988_rule'
  tag stig_id: 'SRG-NET-000166-VPN-000580'
  tag gtitle: 'SRG-NET-000166'
  tag fix_id: 'F-7476r378270_fix'
  tag 'documentable'
  tag legacy: ['SV-106241', 'V-97103']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
