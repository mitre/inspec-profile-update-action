control 'SV-215748' do
  title 'The BIG-IP Core implementation must be configured to use NIST SP 800-52 Revision 1 compliant cryptography to protect the integrity of remote access sessions to virtual servers.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of their intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the BIG-IP Core does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS gateways, and webmail proxy views) for virtual servers, this is not applicable.

When intermediary services for remote access communication traffic are provided, verify the BIG-IP Core uses NIST SP 800-52 Revision 1 compliant cryptography to protect the integrity of remote access sessions to virtual servers.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Configuration" section, that a FIPS-compliant profile is in the "Selected" area for "SSL Profile (Client)" and "SSL Profile (Server)".

If the BIG-IP Core is not configured to use NIST SP 800-52 Revision 1 compliant cryptography to protect the integrity of remote access sessions, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the BIG-IP Core to use NIST SP 800-52 Revision 1 compliant cryptography to protect the integrity of remote access sessions to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16940r291057_chk'
  tag severity: 'medium'
  tag gid: 'V-215748'
  tag rid: 'SV-215748r557356_rule'
  tag stig_id: 'F5BI-LT-000037'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-16938r291058_fix'
  tag 'documentable'
  tag legacy: ['SV-74707', 'V-60277']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
