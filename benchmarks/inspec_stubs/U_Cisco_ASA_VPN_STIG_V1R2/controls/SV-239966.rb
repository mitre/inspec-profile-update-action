control 'SV-239966' do
  title 'The Cisco ASA remote access VPN server must be configured to use LDAP over SSL to determine authorization for granting access to the network.'
  desc 'Protecting authentication communications between the client, the VPN Gateway, and the authentication server keeps this critical information from being exploited.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit as part of the access authorization information, supporting security attributes. This is due to the fact that in distributed information systems, there are various access control decisions that need to be made and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.

This applies to VPN gateways that have the concept of a user account and have the login function residing on the VPN gateway.'
  desc 'check', 'Step 1: Verify that authorization is enforced as shown in the example below.

tunnel-group ANY_CONNECT type remote-access
tunnel-group ANY_CONNECT general-attributes
 authorization-server-group LDAP
 authorization-required
 
Step 2: Verify that LDAP over SSL has been enabled.

aaa-server LDAP protocol ldap
aaa-server LDAP (INSIDE) host 10.1.1.1
 ldap-over-ssl enable

If the ASA is not configured to use LDAP over SSL to determine authorization for granting access to the network, this is a finding.'
  desc 'fix', 'Step 1: Configure the ASA to use LDAP over SSL as shown in the example below.

ASA2(config)# aaa-server LDAP protocol ldap
ASA2(config)# aaa-server LDAP (INSIDE) host 10.1.1.1
ASA2(config-aaa-server-host)# ldap-over-ssl enable 
ASA2(config-aaa-server-host)# exit

Step 2: Configure the ASA to enforce authorization using the common name (CN) from the user’s certificate.

ASA2(config)# tunnel-group ANY_CONNECT general-attributes
ASA2(config-tunnel-general)# authorization-required 
ASA2(config-tunnel-general)# authorization-server-group LDAP
ASA2(config-tunnel-general)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43199r666302_chk'
  tag severity: 'medium'
  tag gid: 'V-239966'
  tag rid: 'SV-239966r856174_rule'
  tag stig_id: 'CASA-VN-000400'
  tag gtitle: 'SRG-NET-000320-VPN-001120'
  tag fix_id: 'F-43158r666303_fix'
  tag 'documentable'
  tag cci: ['CCI-002353']
  tag nist: ['AC-24 (1)']
end
