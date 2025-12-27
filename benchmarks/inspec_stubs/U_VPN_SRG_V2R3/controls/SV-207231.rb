control 'SV-207231' do
  title 'The VPN Gateway must transmit organization-defined access authorization information using FIPS 140-2-validated cryptography to a compliant authentication server, which enforces access control decisions.'
  desc 'Protecting authentication communications between the client, the VPN Gateway, and the authentication server keeps this critical information from being exploited.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit as part of the access authorization information, supporting security attributes. This is due to the fact that in distributed information systems, there are various access control decisions that need to be made and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.

This applies to VPN gateways that have the concept of a user account and have the login function residing on the VPN gateway.'
  desc 'check', 'Verify the VPN Gateway transmits organization-defined access authorization information using FIPS 140-2-validated cryptography to a compliant authentication server, which enforces access control decisions.

If the VPN Gateway does not transmit organization-defined access authorization information using FIPS 140-2-validated cryptography to a compliant authentication server, which enforces access control decisions, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to transmit organization-defined access authorization information using FIPS 140-2-validated cryptography to a compliant authentication server, which enforces access control decisions.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7491r378314_chk'
  tag severity: 'medium'
  tag gid: 'V-207231'
  tag rid: 'SV-207231r608988_rule'
  tag stig_id: 'SRG-NET-000320-VPN-001120'
  tag gtitle: 'SRG-NET-000320'
  tag fix_id: 'F-7491r378315_fix'
  tag 'documentable'
  tag legacy: ['V-97141', 'SV-106279']
  tag cci: ['CCI-002353']
  tag nist: ['AC-24 (1)']
end
