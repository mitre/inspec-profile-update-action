control 'SV-239965' do
  title 'The Cisco ASA remote access VPN server must be configured to use a separate authentication server than that used for administrative access.'
  desc 'The VPN interacts directly with public networks and devices and should not contain user authentication information for all users. AAA network security services provide the primary framework through which a network administrator can set up access control and authorization on network points of entry or network access servers. It is not advisable to configure access control on the VPN gateway or remote access server. Separation of services provides added assurance to the network if the access control server is compromised.'
  desc 'check', 'In the example below, radius server at 10.1.1.2 is used for administrative access authentication while the LDAP server will be used for granting remote access to the network.

aaa-server LDAP protocol ldap
aaa-server LDAP (INSIDE) host 10.1.1.1
…
…
…
aaa-server RADIUS_GROUP protocol radius
aaa-server RADIUS_GROUP (INSIDE) host 10.1.1.2
 key *****
…
…
…
aaa authentication serial console RADIUS_GROUP LOCAL
aaa authentication ssh console RADIUS_GROUP LOCAL

If the ASA is not configured to use a separate authentication server than that used for administrative access, this is a finding.'
  desc 'fix', 'Configure the ASA to use a separate authentication server as shown in the example below.

ASA2(config)# aaa-server LDAP protocol ldap
ASA2(config)# aaa-server LDAP (INSIDE) host 10.1.1.1'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43198r666299_chk'
  tag severity: 'medium'
  tag gid: 'V-239965'
  tag rid: 'SV-239965r666301_rule'
  tag stig_id: 'CASA-VN-000390'
  tag gtitle: 'SRG-NET-000166-VPN-000580'
  tag fix_id: 'F-43157r666300_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
