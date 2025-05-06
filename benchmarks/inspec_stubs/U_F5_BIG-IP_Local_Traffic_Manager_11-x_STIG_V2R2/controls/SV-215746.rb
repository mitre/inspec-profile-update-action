control 'SV-215746' do
  title 'The BIG-IP Core implementation must be configured to use encryption services that implement NIST SP 800-52 Revision 2 compliant cryptography to protect the confidentiality of connections to virtual servers.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of their intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the BIG-IP Core does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS, and webmail) for virtual servers, this is not applicable.

When intermediary services for remote access communications are provided, verify the BIG-IP Core is configured to use encryption services that implement NIST SP 800-52 Revision 2 compliant cryptography to protect the confidentiality of connections to virtual servers.

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> SSL >> Client

Verify a profile exists that is FIPS compliant.

Select FIPS-compliant profile.

Verify "Ciphers" under "Configuration" section is configured to use FIPS-compliant ciphers.

Verify the BIG-IP Core is configured to use a FIPS-compliant profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Configuration" section, that FIPS-compliant profile is in the "Selected" area for "SSL Profile (Client)".

If the BIG-IP Core is not configured to use encryption services that implement NIST  SP 800-52 Revision 1 compliant cryptography to protect the confidentiality of connections to virtual servers, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the BIG-IP Core to use encryption services that implement NIST SP 800-52 Revision 2 compliant cryptography to protect the confidentiality of connections to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16938r513221_chk'
  tag severity: 'medium'
  tag gid: 'V-215746'
  tag rid: 'SV-215746r557356_rule'
  tag stig_id: 'F5BI-LT-000033'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-16936r513222_fix'
  tag 'documentable'
  tag legacy: ['V-60273', 'SV-74703']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
